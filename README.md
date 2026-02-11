# AI-Powered HTTP Request Analysis Pipeline

This project implements a sophisticated pipeline for analyzing HTTP requests using a combination of a rule-engine, Retrieval-Augmented Generation (RAG), and Large Language Models (LLMs). The system is built with a "cache-first" architecture to ensure high performance and low latency for repeated requests.

## Architecture

The pipeline is designed as a state machine using LangGraph. It processes incoming HTTP requests through a series of nodes, each responsible for a specific task. The cache-first approach significantly speeds up the analysis by immediately returning results for known requests.

### Flow Diagram

The following diagram illustrates the complete workflow of the request analysis pipeline:

![LangGraph Flow](artifacts/langgraph.png)

### Key Components

-   **Request Decoder**: The entry point of the pipeline, responsible for decoding and normalizing the incoming HTTP request.
-   **Cache Check**: Checks if the request has been analyzed before. If a result is found in the cache, it's immediately returned, and the pipeline terminates early (Cache HIT).
-   **Rule Engine**: A fast, preliminary check for known malicious patterns. If the request is flagged here, it's immediately classified without needing the LLM.
-   **Router**: Directs the flow based on the output of the rule engine. It decides whether the request needs further analysis by the RAG or LLM nodes.
-   **RAG (Retrieval-Augmented Generation)**: Enriches the request with relevant context from a database of known attack patterns (CSIC2010 dataset) before sending it to the LLM. This improves the accuracy of the final analysis.
-   **LLM (Large Language Model)**: Performs the core analysis of the request, leveraging the context provided by the RAG system to determine if it's malicious or benign.
-   **Cache Save**: Stores the final analysis result in the cache for future lookups.
-   **Response Builder**: Formats the final output.

## Getting Started

### Prerequisites

-   Python 3.10+
-   Pip for package management

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/VyyKa/AI-Analysis-HTTP.git
    cd AI-Analysis-HTTP
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python -m venv venv_langgraph
    source venv_langgraph/Scripts/activate
    ```

3.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set up your API keys:**
    Create a `.env` file in the root directory and add your Groq API key:
    ```
    GROQ_API_KEY="your_groq_api_key"
    ```

### Seeding the RAG Database

The RAG system relies on a ChromaDB vector store populated with data from the `nquangit/CSIC2010_dataset_classification` dataset. To set this up, run the seeding script:

```bash
python seed_rag.py
```

This will download the dataset, generate embeddings, and populate the local ChromaDB instance in the `chroma_db/` directory.

## Usage

You can interact with the analysis pipeline through the provided FastAPI application.

1.  **Run the API server:**
    ```bash
    uvicorn api:app --reload
    ```

2.  **Send a request for analysis:**
    Use a tool like `curl` or Postman to send a `POST` request to the `/analyze` endpoint.

    **Example using `curl`:**
    ```bash
    curl -X POST "http://127.0.0.1:8000/analyze" -H "Content-Type: application/json" -d '{"request": "GET /?q=<script>alert(1)</script> HTTP/1.1\nHost: example.com"}'
    ```

    The API will return a JSON object with the detailed analysis, including the final verdict (attack or normal) and an explanation from the LLM.
