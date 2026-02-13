from fastapi import FastAPI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from graph_app import soc_app

app = FastAPI(title="SOC LangGraph API")

@app.get("/health")
def health_check():
    """Health check endpoint for Docker"""
    return {"status": "healthy", "service": "soc-analysis"}

@app.post("/analyze")
def analyze(payload: dict):
    """
    Analyze HTTP requests for security threats.
    
    Request body:
    {
      "requests": [
        "hello world",
        "id=1 UNION SELECT password FROM users"
      ]
    }
    """
    return soc_app.invoke(payload)
