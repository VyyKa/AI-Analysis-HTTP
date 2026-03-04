import os
import logging
import httpx
from dotenv import load_dotenv

load_dotenv(override=True)

from groq import Groq

logger = logging.getLogger(__name__)

client = Groq(
    api_key=os.getenv("GROQ_API_KEY"),
    http_client=httpx.Client(verify=False),
)

SYSTEM_PROMPT = """You are a Senior AppSec Engineer analyzing HTTP requests for a SOC system.
Your job is to deeply analyze the request and the provided RAG context to determine if the request is an attack.

Rules:
1. You MUST respond in STRICT JSON format. Do not add markdown blocks like ```json or any other text.
2. If the request is benign or generic text, marked it safely.
3. Be highly mindful of False Positives. Common words (like 'select', 'union') in standard sentences are NOT attacks unless they form a syntax structure.
4. Assess for SQLi, XSS, Command Injection, Path Traversal, SSRF, SSTI, etc.
5. If you see encoded payloads (Base64, Hex) that decode to attacks, flag them.
6. Provide a recommendation for remediation or further investigation.

You MUST output EXACTLY this JSON structure:
{
  "threat_score": <int from 0 to 10. 0=Benign, 10=Critical Attack>,
  "attack_type": "<String. 'Benign', 'SQL Injection', 'XSS', 'Unknown', etc.>",
  "justification": "<String. Max 2 sentences explaining WHY you gave this score>",
  "action": "<String. 'ALLOW', 'REVIEW', or 'BLOCK'>",
  "recommendation": "<String. Max 2 sentences for remediation or further investigation>"
}
"""

MODEL = "llama-3.1-8b-instant"


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


def _truncate_text(text: str, max_chars: int) -> str:
    value = str(text or "")
    if len(value) <= max_chars:
        return value
    return value[:max_chars] + "\n... [truncated]"


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
        completion = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            temperature=0.1,
            max_tokens=_bulk_max_tokens(len(queries)),
            response_format={"type": "json_object"}
        )
        verdict = completion.choices[0].message.content.strip()
        import json
        try:
            parsed = json.loads(verdict)
            payload_list = None
            if isinstance(parsed, dict):
                maybe_results = parsed.get("results")
                if isinstance(maybe_results, list):
                    payload_list = maybe_results
            elif isinstance(parsed, list):
                payload_list = parsed

            if isinstance(payload_list, list) and len(payload_list) == len(queries):
                return [{"analysis": obj, "model": MODEL, "raw_text": verdict} for obj in payload_list]
            logger.warning("Bulk LLM malformed result size; fallback to single calls.")
        except json.JSONDecodeError:
            logger.warning("Bulk LLM returned invalid JSON; fallback to single calls.")
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

    try:
        completion = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            temperature=0.1, # Lower temperature for more deterministic JSON
            max_tokens=250,
            response_format={"type": "json_object"} # Force JSON output if supported
        )
        verdict = completion.choices[0].message.content.strip()
        
        # The response_format={"type": "json_object"} should ensure valid JSON,
        # so explicit markdown cleanup is less necessary.
        # If the model still outputs markdown, the JSONDecodeError will catch it.
            
        import json
        try:
            parsed_json = json.loads(verdict)
            return {
                "analysis": parsed_json, 
                "model": MODEL,
                "raw_text": verdict
            }
        except json.JSONDecodeError:
            logger.error(f"Failed to parse LLM JSON: {verdict}")
            return {
                "analysis": {
                    "threat_score": 0,
                    "attack_type": "Parse Error",
                    "justification": "LLM failed to output valid JSON.",
                    "action": "REVIEW",
                    "recommendation": "Review LLM output for malformed JSON."
                },
                "model": MODEL,
                "raw_text": verdict
            }

    except Exception as e:
        logger.warning("Groq API unavailable (%s): %s. Using fallback.", type(e).__name__, e)
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
