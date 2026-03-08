import os
import logging
import httpx
import json
import re
from dotenv import load_dotenv

load_dotenv(override=True)

from groq import Groq

logger = logging.getLogger(__name__)

client = Groq(
    api_key=os.getenv("GROQ_API_KEY"),
    http_client=httpx.Client(verify=False),
)

SYSTEM_PROMPT = """You are a Senior Application Security Engineer working in a SOC analyzing HTTP requests for potential attacks.
Your task is to determine whether the ACTUAL HTTP REQUEST contains malicious content.
STRICT ANALYSIS SCOPE
You must ONLY analyze the section labeled HTTP REQUEST.
The section RELATED CONTEXT (RAG) contains examples from a knowledge base used for reference only.
IMPORTANT:
- The RAG examples are NOT part of the request
- They may contain attack payloads that DO NOT exist in the request
- You must NEVER treat RAG examples as evidence of an attack
- Evidence must appear directly inside the HTTP REQUEST
If the payload exists only in RAG and not in the request, it is NOT an attack.
FALSE POSITIVE PREVENTION RULES
Do NOT flag attacks for:
- random text
- generic words
- test inputs like:
  test
  hello
  aaaa
  sample
  example
Words like:
select
union
script
admin
are NOT attacks unless they appear in valid attack syntax.
DETECTION RULES
Evaluate the HTTP request for:
SQL Injection
Cross-Site Scripting (XSS)
Command Injection
Path Traversal
Server-Side Request Forgery (SSRF)
Server-Side Template Injection (SSTI)
File Inclusion
Deserialization attacks
Encoded payloads must ONLY be analyzed if they appear inside the HTTP REQUEST.
If you see encoded strings in the request:
Base64
Hex
URL encoding
then decode them and inspect the result.
EVIDENCE REQUIREMENT
If you detect an attack, you MUST:
- Quote the exact substring from the HTTP REQUEST
- Explain why that substring is malicious
If no malicious content appears in the request:
threat_score must be 0
attack_type must be "Benign"
action must be "ALLOW"
SCORING GUIDE
0 → Benign request
1-3 → Suspicious but likely benign
4-6 → Possible attack
7-8 → Confirmed attack
9-10 → Critical attack attempt
OUTPUT FORMAT (STRICT JSON ONLY)
Return ONLY valid JSON.
Do not include markdown blocks, explanations, or extra text.
{
  "threat_score": <integer 0-10>,
  "attack_type": "<Benign | SQL Injection | XSS | Command Injection | Path Traversal | SSRF | SSTI | Unknown>",
  "justification": "<max 2 sentences explaining the decision. Quote evidence from HTTP REQUEST if present>",
  "action": "<ALLOW | REVIEW | BLOCK>",
  "recommendation": "<max 2 sentences with security advice>"
}
DECISION LOGIC
If no malicious pattern appears in the HTTP request:
- threat_score = 0
- attack_type = "Benign"
- action = "ALLOW"
Never classify an attack based only on RAG examples.
"""

MODEL = os.getenv("LLM_MODEL", "openai/gpt-oss-120b")
FALLBACK_MODEL = os.getenv("LLM_FALLBACK_MODEL", "llama-3.3-70b-versatile")


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


USE_JSON_RESPONSE_FORMAT = _env_bool("LLM_ENFORCE_JSON_RESPONSE_FORMAT", False)


def _create_chat_completion(messages: list[dict], max_tokens: int, model: str):
    request = {
        "model": model,
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": max_tokens,
    }
    if USE_JSON_RESPONSE_FORMAT:
        request["response_format"] = {"type": "json_object"}

    try:
        return client.chat.completions.create(**request)
    except Exception as e:
        if request.get("response_format") and "json_validate_failed" in str(e).lower():
            logger.warning("Groq json_validate_failed; retrying without response_format.")
            request.pop("response_format", None)
            return client.chat.completions.create(**request)
        raise


def _analyze_with_model(messages: list[dict], max_tokens: int, model: str):
    completion = _create_chat_completion(messages, max_tokens, model)
    verdict = completion.choices[0].message.content.strip()
    parsed_json = _parse_json_payload(verdict)
    if isinstance(parsed_json, dict):
        return {
            "analysis": parsed_json,
            "model": model,
            "raw_text": verdict,
        }, verdict
    return None, verdict


def _truncate_text(text: str, max_chars: int) -> str:
    value = str(text or "")
    if len(value) <= max_chars:
        return value
    return value[:max_chars] + "\n... [truncated]"


def _strip_markdown_code_fence(text: str) -> str:
    value = str(text or "").strip()
    if not value.startswith("```"):
        return value
    value = re.sub(r"^```[a-zA-Z0-9_+\-]*\s*", "", value)
    value = re.sub(r"\s*```$", "", value)
    return value.strip()


def _parse_json_payload(text: str):
    payload = _strip_markdown_code_fence(text)
    candidates = [payload]

    obj_start = payload.find("{")
    obj_end = payload.rfind("}")
    if obj_start != -1 and obj_end != -1 and obj_end > obj_start:
        candidates.insert(0, payload[obj_start:obj_end + 1])

    arr_start = payload.find("[")
    arr_end = payload.rfind("]")
    if arr_start != -1 and arr_end != -1 and arr_end > arr_start:
        candidates.insert(0, payload[arr_start:arr_end + 1])

    seen = set()
    for candidate in candidates:
        body = str(candidate or "").strip()
        if not body or body in seen:
            continue
        seen.add(body)
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            continue
    return None


def _bulk_max_tokens(batch_size: int) -> int:
    # Keep responses bounded to avoid very large generations on heavy batches.
    token_cap = _env_int("LLM_BULK_MAX_TOKENS_CAP", 4096)
    estimated = 180 * max(batch_size, 1) + 256
    return max(512, min(token_cap, estimated))


def llm_bulk_analyze(queries: list[str], rag_contexts: list[str]) -> list[dict]:
    """Send a batch of requests to Groq in a single API call.

    Returns a list of result dictionaries in the same order as *queries*.
    If the model fails to output valid JSON array, falls back to calling
    ``llm_analyze`` individually.
    """
    if not queries:
        return []

    max_query_chars = _env_int("LLM_MAX_QUERY_CHARS", 1500)
    max_rag_chars = _env_int("LLM_MAX_RAG_CHARS", 2000)

    # Build combined user message
    combined = []
    for idx, (q, ctx) in enumerate(zip(queries, rag_contexts), start=1):
        q_view = _truncate_text(q, max_query_chars)
        ctx_view = _truncate_text(ctx or "None", max_rag_chars)
        combined.append(f"=== REQUEST {idx} ===\nHTTP REQUEST:\n{q_view}\n\nRELATED CONTEXT (RAG):\n{ctx_view}")
    user_prompt = (
        "\n\n".join(combined)
        + "\n\nAnalyze each request above and return STRICT JSON object: "
        + '{"results": [ {"threat_score": int, "attack_type": str, "justification": str, "action": str, "recommendation": str}, ... ]}'
        + ". The number of objects in results must equal the number of requests."
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    try:
        completion = _create_chat_completion(messages, _bulk_max_tokens(len(queries)), MODEL)
        verdict = completion.choices[0].message.content.strip()
        parsed = _parse_json_payload(verdict)
        payload_list = None
        if isinstance(parsed, dict):
            maybe_results = parsed.get("results")
            if isinstance(maybe_results, list):
                payload_list = maybe_results
        elif isinstance(parsed, list):
            payload_list = parsed

        if isinstance(payload_list, list) and len(payload_list) == len(queries):
            return [{"analysis": obj, "model": MODEL, "raw_text": verdict} for obj in payload_list]
        logger.warning("Bulk LLM malformed or invalid JSON result; fallback to single calls.")
    except Exception as e:
        logger.warning("Bulk LLM call failed (%s): %s. Falling back to individual.", type(e).__name__, e)

    # fallback: call one-by-one
    results = []
    for q, ctx in zip(queries, rag_contexts):
        results.append(llm_analyze(q, ctx))
    return results


def llm_analyze(query: str, rag_context: str) -> dict:
    """
    Run Groq LLM analysis for a single query.
    Called ONLY when request is NOT blocked by rule engine and cache MISS.
    Falls back to a safe default if the API is unreachable.
    """
    max_query_chars = _env_int("LLM_MAX_QUERY_CHARS", 1500)
    max_rag_chars = _env_int("LLM_MAX_RAG_CHARS", 2000)
    query_view = _truncate_text(query, max_query_chars)
    context_view = _truncate_text(rag_context or "None", max_rag_chars)

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"HTTP REQUEST:\n{query_view}\n\nRELATED CONTEXT (RAG):\n{context_view}\n\nAnalyze this request and return JSON.",
        },
    ]

    primary_error = None
    fallback_error = None
    primary_raw = ""
    fallback_raw = ""

    try:
        primary_result, primary_raw = _analyze_with_model(messages, 250, MODEL)
        if primary_result is not None:
            return primary_result
    except Exception as e:
        primary_error = e
        logger.warning("Primary model call failed (%s): %s", type(e).__name__, e)

    if FALLBACK_MODEL and FALLBACK_MODEL != MODEL:
        try:
            logger.warning("Primary model did not return valid JSON. Retrying with fallback model %s", FALLBACK_MODEL)
            fallback_result, fallback_raw = _analyze_with_model(messages, 250, FALLBACK_MODEL)
            if fallback_result is not None:
                return fallback_result
        except Exception as e:
            fallback_error = e
            logger.warning("Fallback model call failed (%s): %s", type(e).__name__, e)

    if primary_error is not None and (not FALLBACK_MODEL or FALLBACK_MODEL == MODEL or fallback_error is not None):
        chosen_error = fallback_error or primary_error
        logger.warning("Groq API unavailable (%s): %s. Using fallback.", type(chosen_error).__name__, chosen_error)
        return {
            "analysis": {
                "threat_score": 0,
                "attack_type": "Benign",
                "justification": "LLM unavailable, fallback verdict.",
                "action": "ALLOW"
            },
            "model": f"{MODEL} (fallback)",
            "raw_text": ""
        }

    raw_for_debug = primary_raw or fallback_raw
    logger.error("Failed to parse LLM JSON: %s", raw_for_debug)
    return {
        "analysis": {
            "threat_score": 0,
            "attack_type": "Parse Error",
            "justification": "LLM failed to output valid JSON.",
            "action": "REVIEW",
            "recommendation": "Review LLM output for malformed JSON."
        },
        "model": MODEL,
        "raw_text": raw_for_debug
    }
