import os
from dotenv import load_dotenv
from groq import Groq

# =====================================================
# Load environment variables from .env
# =====================================================
load_dotenv()

# =====================================================
# Initialize Groq client
# =====================================================
client = Groq(
    api_key=os.getenv("GROQ_API_KEY")
)

# =====================================================
# System prompt for SOC analysis
# =====================================================
SYSTEM_PROMPT = """You are a SOC analyst.

Rules:
- If the request is clearly benign or generic text, respond EXACTLY with:
  "Benign request – no malicious intent detected."

- Only mark as malicious if there are concrete indicators
  (e.g. SQL keywords, script injection, traversal patterns).

- Do NOT guess.
- Do NOT over-classify.
"""


# =====================================================
# LLM analyze function
# =====================================================
def llm_analyze(query: str, rag_context: str) -> dict:
    """
    Run Groq LLM analysis.
    This function is called ONLY when:
    - Request is NOT blocked by rule engine
    - Cache MISS
    """

    messages = [
        {
            "role": "system",
            "content": SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": f"""
HTTP REQUEST:
{query}

RELATED CONTEXT (RAG):
{rag_context if rag_context else "None"}

Return a concise security verdict.
""",
        },
    ]

    completion = client.chat.completions.create(
        model="llama-3.3-70b-versatile",  # ✅ ACTIVE model (per Groq dashboard)
        messages=messages,
        temperature=0.2,
        max_tokens=150,
    )

    verdict = completion.choices[0].message.content.strip()

    return {
        "analysis": verdict,        
        "model": "llama-3.3-70b-versatile",
    }
