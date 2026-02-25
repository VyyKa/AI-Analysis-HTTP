import os
import logging
import httpx
from dotenv import load_dotenv
from groq import Groq


load_dotenv()
print("[DEBUG] GROQ_API_KEY:", os.getenv("GROQ_API_KEY"))

logger = logging.getLogger(__name__)

client = Groq(
    api_key=os.getenv("GROQ_API_KEY"),
    http_client=httpx.Client(verify=False),
)

SYSTEM_PROMPT = """You are a SOC analyst.

Rules:
- If the request is clearly benign or generic text, respond EXACTLY with:
  "Benign request – no malicious intent detected."

- Only mark as malicious if there are concrete indicators
  (e.g. SQL keywords, script injection, traversal patterns).

- Do NOT guess.
- Do NOT over-classify.
"""

MODEL = "llama-3.1-8b-instant"


def llm_analyze(query: str, rag_context: str) -> dict:
    """
    Run Groq LLM analysis.
    Called ONLY when request is NOT blocked by rule engine and cache MISS.
    Falls back to a safe default if the API is unreachable.
    """
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"HTTP REQUEST:\n{query}\n\nRELATED CONTEXT (RAG):\n{rag_context or 'None'}\n\nReturn a concise security verdict.",
        },
    ]

    try:
        completion = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            temperature=0.2,
            max_tokens=150,
        )
        verdict = completion.choices[0].message.content.strip()
        return {"analysis": verdict, "model": MODEL}

    except Exception as e:
        logger.warning("Groq API unavailable (%s): %s. Using fallback.", type(e).__name__, e)
        return {
            "analysis": "Benign request \u2013 no malicious intent detected. (LLM unavailable, fallback verdict)",
            "model": f"{MODEL} (fallback)",
        }
