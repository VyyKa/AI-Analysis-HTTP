from fastapi import FastAPI
from graph_app import soc_app

app = FastAPI(title="SOC LangGraph API")

@app.post("/analyze")
def analyze(payload: dict):
    """
    {
      "requests": [
        "hello world",
        "id=1 UNION SELECT password FROM users"
      ]
    }
    """
    return soc_app.invoke(payload)
