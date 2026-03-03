import os
import logging
import httpx
from dotenv import load_dotenv

load_dotenv(override=True)
print("[DEBUG] GROQ_API_KEY:", os.getenv("GROQ_API_KEY"))

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


def llm_analyze(query: str, rag_context: str) -> dict:
    """
    Run Groq LLM analysis for a single query.
    Called ONLY when request is NOT blocked by rule engine and cache MISS.
    Falls back to a safe default if the API is unreachable.
    """
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"HTTP REQUEST:\n{query}\n\nRELATED CONTEXT (RAG):\n{rag_context or 'None'}\n\nAnalyze this request and return JSON.",
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
