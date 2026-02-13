# 📦 Docker Packaging Summary

## Các File Đã Tạo

### 1. `Dockerfile`
- Multi-stage build để giảm image size
- Base image: `python:3.13-slim`
- Install dependencies minimal
- Expose port 8000 (FastAPI)
- Health check tự động

### 2. `docker-compose.yml`
- 2 services:
  - `soc-app`: Python application (FastAPI + LangGraph)
  - `qdrant`: Vector database
- Network isolation
- Volume persistence:
  - `qdrant_storage`: Qdrant data
  - `app_logs`: Application logs
- Health checks với dependency chaining

### 3. `requirements-minimal.txt`
- Chỉ dependencies cần thiết:
  - FastAPI + Uvicorn
  - LangGraph + LangChain
  - Qdrant client
  - SentenceTransformers
  - Groq client
- Không có Windows-specific packages (pywin32)

### 4. `.dockerignore`
- Loại bỏ:
  - venv, __pycache__
  - .git, docs
  - Các file test, cache cũ
  - Files chỉ dùng development

### 5. App-only Compose (Qdrant chạy riêng)
- `docker-compose.app-only.yml`: Chỉ chạy `soc-app`, Qdrant trỏ đến server ngoài
- Dùng khi deploy production với Qdrant chung

### 6. Scripts Hỗ Trợ
- `start.sh` (Linux/Mac)
- `start.bat` (Windows)
- `Makefile` (shortcuts cho Docker commands)

### 7. Documentation
- `README_DOCKER.md`: Hướng dẫn chi tiết
- Bao gồm troubleshooting, deployment, monitoring

---

## Cách Sử Dụng

### Quick Start (Windows)

```cmd
# Edit .env với GROQ_API_KEY
notepad .env

# Chạy script auto
start.bat
```

### Quick Start (Linux/Mac)

```bash
# Edit .env
nano .env

# Run script
chmod +x start.sh
./start.sh
```

### Manual Commands

```bash
# Build (full stack)
docker-compose build

# Start (full stack)
docker-compose up -d

# Start app-only (Qdrant ngoài)
docker-compose -f docker-compose.app-only.yml up -d

# Seed Qdrant data
docker exec -it soc-app python scripts/seed_rag_from_csic.py

# Test API
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"requests": ["/api/test"]}'

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### Makefile Shortcuts

```bash
make help       # Show all available commands
make dev        # Build, start, and show logs
make seed       # Seed Qdrant data
make test       # Test API endpoint
make health     # Check service health
make backup     # Backup Qdrant data
make clean      # Remove containers & volumes
```

---

## Image Size

Estimated final image sizes:
- **soc-app**: ~3-4 GB (do PyTorch + CUDA libs cho SentenceTransformers)
- **qdrant**: ~100-200 MB (official slim image)

**Total disk usage**: ~4-5 GB cho cả 2 images + volumes

---

## Performance

### Resource Recommendations

| Deployment | CPU | RAM | Disk | Concurrent Requests |
|-----------|-----|-----|------|-------------------|
| **Minimal** | 2 cores | 2 GB | 10 GB | 1-5 |
| **Recommended** | 4 cores | 4 GB | 20 GB | 20-30 |
| **High Load** | 8 cores | 8 GB | 30 GB | 50+ |

### Tuning

**docker-compose.yml resource limits:**

```yaml
soc-app:
  deploy:
    resources:
      limits:
        cpus: '4.0'
        memory: 4G
      reservations:
        cpus: '2.0'
        memory: 2G
```

---

## Deployment Checklist

- [ ] ✅ `.env` file configured with `GROQ_API_KEY`
- [ ] ✅ Docker & Docker Compose installed
- [ ] ✅ Port 8000 và 6333 available
- [ ] ✅ Minimum 10GB disk space available
- [ ] ✅ Build images: `docker-compose build`
- [ ] ✅ Start services: `docker-compose up -d`
- [ ] ✅ Seed Qdrant: `docker exec -it soc-app python scripts/seed_rag_from_csic.py`
- [ ] ✅ Test API: `curl http://localhost:8000/health`
- [ ] ✅ Check logs: `docker-compose logs -f`

---

## Troubleshooting

### Build Fails

```bash
# Clear cache and rebuild
docker-compose build --no-cache

# Check Docker daemon
docker ps

# Check disk space
docker system df
```

### Container Won't Start

```bash
# Check logs
docker-compose logs soc-app

# Check if port is occupied
netstat -ano | findstr :8000  # Windows
lsof -i :8000  # Linux/Mac

# Restart services
docker-compose restart
```

### Qdrant Data Missing

```bash
# Check volume
docker volume ls

# Check collection
docker exec -it soc-app python -c "
from backends.rag_backend import client, COLLECTION_NAME
print(client.get_collection(COLLECTION_NAME))
"

# Re-seed
docker exec -it soc-app python scripts/seed_rag_from_csic.py
```

---

## Next Steps

1. **Production deployment**:
   - Add nginx reverse proxy
   - Setup SSL/TLS certificates
   - Configure logging aggregation
   - Setup monitoring (Prometheus/Grafana)

2. **Scaling**:
   - Use Docker Swarm or Kubernetes
   - Add load balancer
   - Separate Qdrant to dedicated server

3. **CI/CD**:
   - Automate builds on GitHub Actions
   - Push images to Docker Hub/Registry
   - Auto-deploy on tag/release

---

## Production Security

```yaml
# docker-compose.prod.yml
version: "3.9"
services:
  soc-app:
    environment:
      - GROQ_API_KEY=${GROQ_API_KEY}
      - QDRANT_URL=http://qdrant:6333
    restart: always
    read_only: true  # Filesystem read-only
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
```

---

## Summary

✅ **Hoàn thành Dockerization**:
- Toàn bộ project đóng gói trong Docker
- 1 command để build & run
- Dễ deploy trên bất kỳ server nào
- Isolation và reproducibility
- Ready cho production

**Size**: ~4-5GB total
**Start time**: ~30-60 giây
**Performance**: Giống như chạy local venv
