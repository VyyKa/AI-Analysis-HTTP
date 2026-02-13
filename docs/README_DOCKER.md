# 🐳 Docker Deployment Guide

## Quick Start

### 1️⃣ Chuẩn bị Environment

```bash
# Copy file .env.example thành .env
cp .env.example .env

# Edit .env và thêm GROQ_API_KEY
nano .env  # hoặc notepad .env trên Windows
```

File `.env` cần có:
```env
GROQ_API_KEY=your_api_key_here
QDRANT_URL=http://qdrant:6333
QDRANT_COLLECTION=soc_attacks
```

---

### 2️⃣ Build và Chạy

```bash
# Build images
docker-compose build

# Khởi động tất cả services (Qdrant + App)
docker-compose up -d

# Xem logs
docker-compose logs -f soc-app
```

### App-only (Qdrant chạy riêng trên server)

```bash
# .env phải trỏ đến Qdrant server
# QDRANT_URL=http://<qdrant-server>:6333

# Build app image
docker-compose -f docker-compose.app-only.yml build

# Chạy app-only
docker-compose -f docker-compose.app-only.yml up -d

# Xem logs
docker-compose -f docker-compose.app-only.yml logs -f soc-app
```

---

### 3️⃣ Seed Data vào Qdrant

```bash
# Chạy migration script để load data vào Qdrant
docker exec -it soc-app python scripts/migrate_chroma_to_qdrant.py

# Hoặc seed từ CSIC2010
docker exec -it soc-app python scripts/seed_rag_from_csic.py
```

---

### 4️⃣ Test API

```bash
# Health check
curl http://localhost:8000/health

# Test analyze endpoint
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      "/api/users?id=1 OR 1=1",
      "/products?category=shoes"
    ]
  }'
```

---

## Quản Lý Services

```bash
# Xem status
docker-compose ps

# Restart services
docker-compose restart

# Stop services (giữ data)
docker-compose stop

# Xóa containers (giữ volumes)
docker-compose down

# Xóa tất cả (bao gồm data)
docker-compose down -v

# Xem logs realtime
docker-compose logs -f

# Xem resource usage
docker stats
```

---

## Troubleshooting

### App không start được

```bash
# Check logs
docker-compose logs soc-app

# Kiểm tra Qdrant đã ready chưa
curl http://localhost:6333/health

# Restart app
docker-compose restart soc-app
```

### Qdrant không có data

```bash
# Check collection
docker exec -it soc-app python -c "
from backends.rag_backend import client, COLLECTION_NAME
print(client.get_collection(COLLECTION_NAME))
"
# Seed lại data
docker exec -it soc-app python scripts/migrate_chroma_to_qdrant.py
```

### Port conflicts

```bash
# Nếu port 8000 hoặc 6333 bị chiếm
# Edit docker-compose.yml:
# ports:
#   - "8001:8000"  # Change 8000 -> 8001
```

---

## Production Deployment

### Resource Limits

Edit `docker-compose.yml`:

```yaml
soc-app:
  # ... other config
  deploy:
    resources:
      limits:
        cpus: '2.0'
        memory: 2G
      reservations:
        cpus: '1.0'
        memory: 1G
```

### Environment-specific configs

```bash
# Development
docker-compose up

# Production
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

---

## Monitoring

```bash
# Container stats
docker stats soc-app soc-qdrant

# Disk usage
docker system df

# Qdrant metrics
curl http://localhost:6333/metrics
```

---

## Backup & Restore

### Backup Qdrant data

```bash
# Backup volume
docker run --rm -v langchain_qdrant_storage:/data -v $(pwd):/backup \
  alpine tar czf /backup/qdrant-backup.tar.gz /data
```

### Restore

```bash
# Restore volume
docker run --rm -v langchain_qdrant_storage:/data -v $(pwd):/backup \
  alpine tar xzf /backup/qdrant-backup.tar.gz -C /
```

---

## Architecture

```
┌─────────────────────────────────────┐
│   User / External Service           │
└──────────────┬──────────────────────┘
               │ HTTP :8000
┌──────────────▼──────────────────────┐
│   soc-app (FastAPI)                 │
│   - LangGraph Pipeline              │
│   - Rule Engine                     │
│   - LLM Integration                 │
└──────────────┬──────────────────────┘
               │ HTTP :6333
┌──────────────▼──────────────────────┐
│   qdrant (Vector DB)                │
│   - 16,225+ vectors                 │
│   - 384-dim embeddings              │
└─────────────────────────────────────┘
```

---

## Performance Tips

1. **Cache warming**: Seed Qdrant trước khi production
2. **Resource allocation**: 
   - Minimum: 2 CPU, 2GB RAM
   - Recommended: 4 CPU, 4GB RAM
3. **Network**: Dùng internal network cho app ↔ Qdrant
4. **Concurrency**: Limit FastAPI workers dựa trên CPU cores

---

## Clean Up

```bash
# Stop và xóa containers + networks
docker-compose down

# Xóa images
docker rmi langchain-soc-app langchain-qdrant

# Xóa volumes (⚠️ mất data)
docker-compose down -v

# Dọn dẹp toàn bộ Docker
docker system prune -a --volumes
```
