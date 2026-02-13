# 🐳 Docker Hub Deployment

## Push Image lên Docker Hub

### 1️⃣ Login Docker Hub

```bash
docker login
# Nhập username và password
```

### 2️⃣ Tag Image

```bash
# Format: docker tag <local-image> <dockerhub-username>/<repo-name>:<tag>
docker tag langchain-soc-app:latest <YOUR_USERNAME>/soc-analysis:latest
docker tag langchain-soc-app:latest <YOUR_USERNAME>/soc-analysis:v1.0

# Ví dụ:
# docker tag langchain-soc-app:latest vyyka/soc-analysis:latest
```

### 3️⃣ Push Image

```bash
docker push <YOUR_USERNAME>/soc-analysis:latest
docker push <YOUR_USERNAME>/soc-analysis:v1.0

# ⚠️ Warning: Image size = 12.4GB, upload sẽ mất 30-60 phút
```

---

## Pull & Run từ Docker Hub

### Cách khác người dùng pull image:

```bash
# Pull image
docker pull <YOUR_USERNAME>/soc-analysis:latest

# Run với docker-compose (recommended)
# Edit docker-compose.yml:
services:
  soc-app:
    image: <YOUR_USERNAME>/soc-analysis:latest  # Thay vì build từ Dockerfile
    # ... rest of config
```

### Hoặc run trực tiếp:

```bash
# Start Qdrant first
docker run -d --name qdrant -p 6333:6333 qdrant/qdrant:latest

# Run app
docker run -d \
  --name soc-app \
  -p 8000:8000 \
  -e GROQ_API_KEY=your_key_here \
  -e QDRANT_URL=http://qdrant:6333 \
  --link qdrant \
  <YOUR_USERNAME>/soc-analysis:latest
```

---

## Giảm Size Image (Optional)

### Tạo Image nhỏ hơn với CPU-only:

Edit `requirements-minimal.txt`:

```txt
# Add this line to use CPU-only PyTorch
--extra-index-url https://download.pytorch.org/whl/cpu

# Then specify CPU version
torch==2.5.1+cpu
sentence-transformers
# ... rest
```

Rebuild:

```bash
docker-compose build --no-cache
# New size: ~2-3GB instead of 12.4GB
```

---

## Alternative: Export/Import Image

### Export image to file (để share qua USB/network):

```bash
# Export
docker save langchain-soc-app:latest | gzip > soc-app-image.tar.gz
# Size: ~4-5GB compressed

# Import on another machine
docker load < soc-app-image.tar.gz
```

---

## Docker Hub Repository Settings

### Tạo Repository trên Docker Hub:

1. Vào https://hub.docker.com
2. Click "Create Repository"
3. Repository name: `soc-analysis`
4. Visibility: Private hoặc Public
5. Description: "SOC HTTP Request Analysis with LangGraph + Qdrant + Groq LLM"

### README trên Docker Hub:

```markdown
# SOC Analysis - HTTP Request Security Scanner

AI-powered security analysis system using LangGraph, Qdrant vector DB, and Groq LLM.

## Quick Start

```bash
# 1. Create .env file
cat > .env << EOF
GROQ_API_KEY=your_groq_api_key
QDRANT_URL=http://qdrant:6333
QDRANT_COLLECTION=soc_attacks
EOF

# 2. Run with docker-compose
docker-compose up -d

# 3. Test API
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"requests": ["/api/users?id=1 OR 1=1"]}'
```

## Features
- ⚡ Fast path detection (5-10ms)
- 🧠 LLM-powered analysis
- 🔍 RAG with 16k+ attack examples
- 📊 Real-time threat scoring
```

---

## Commands Summary

```bash
# Build
docker-compose build

# Tag for Docker Hub
docker tag langchain-soc-app:latest username/soc-analysis:latest

# Login & Push
docker login
docker push username/soc-analysis:latest

# Pull & Run (on other machine)
docker pull username/soc-analysis:latest
docker-compose up -d

# Export/Import
docker save langchain-soc-app:latest | gzip > image.tar.gz
docker load < image.tar.gz
```

---

## Size Comparison

| Version | Size | Use Case |
|---------|------|----------|
| Full (CUDA) | 12.4GB | GPU servers, development |
| CPU-only | ~2-3GB | Production, cloud VMs |
| Compressed export | ~4-5GB | Offline transfer |

---

## Production Recommendations

1. **Push to private registry** (Docker Hub private repo or AWS ECR)
2. **Use multi-stage builds** (already implemented)
3. **Tag versions properly**: `v1.0`, `v1.1`, `latest`
4. **Enable vulnerability scanning** on Docker Hub
5. **Set up CI/CD** to auto-build on git push

---

## CI/CD Integration (GitHub Actions)

```yaml
# .github/workflows/docker-build.yml
name: Build and Push Docker Image

on:
  push:
    branches: [ main, feature/qdrant-rag-context ]
    tags: [ 'v*' ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Login to Docker Hub
        uses: docker/login-action@v2
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}
      
      - name: Build and push
        uses: docker/build-push-action@v4
        with:
          context: .
          push: true
          tags: |
            username/soc-analysis:latest
            username/soc-analysis:${{ github.sha }}
```
