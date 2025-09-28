# ตัวอย่างการใช้งาน API Gateway ที่ Optimized

## การเริ่มต้น

```bash
# Set environment variables
export DATABASE_URL="postgresql://user:password@localhost/db"
export JWT_SECRET="your-secret-key"
export BIND_ADDRESS="0.0.0.0:8000"

# Run the gateway
cargo run
```

## การทดสอบ Performance

### 1. ทดสอบ Cache Hit/Miss

```bash
# First request (cache miss)
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8000/api/projects/123

# Second request (cache hit - should be much faster)
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8000/api/projects/123
```

### 2. ดูสถิติ Cache

```bash
# Check cache statistics
curl http://localhost:8000/admin/cache/stats

# Response:
{
  "total_entries": 25,
  "expired_entries": 2,
  "cache_hit_ratio": null
}
```

### 3. จัดการ Cache

```bash
# Clear all cache
curl -X DELETE http://localhost:8000/admin/cache

# Clear cache for specific user
curl -X DELETE "http://localhost:8000/admin/cache?user_id=user123"
```

## การติดตาม Performance

### Logs ที่สำคัญ

```
INFO fetch_user_roles: cache_hit=true total_roles=3 user_id=user123 resource_id=project456
INFO fetch_user_roles: cache_hit=false total_roles=2 user_id=user789 resource_id=task123
INFO Cleared cache for specific user user_id=user123
```

### Metrics ที่ควรติดตาม

1. **Cache Hit Ratio**: เป้าหมาย > 80%
2. **Response Time**: 
   - Cache hit: < 5ms
   - Cache miss: < 50ms
3. **Database Query Count**: ลดลง 70-90%

## การ Benchmark

### เครื่องมือที่แนะนำ

```bash
# Install wrk for load testing
brew install wrk  # macOS
# หรือ apt-get install wrk  # Ubuntu

# Test with concurrent requests
wrk -t12 -c400 -d30s \
    -H "Authorization: Bearer YOUR_JWT_TOKEN" \
    http://localhost:8000/api/projects/123
```

### ผลลัพธ์ที่คาดหวัง

**ก่อน Optimization:**
```
Requests/sec: 500-800
Latency: 50-100ms
Database queries: 6-8 per request
```

**หลัง Optimization (with cache):**
```
Requests/sec: 2000-5000
Latency: 2-10ms
Database queries: 0-3 per request
```

## การ Deploy Production

### 1. Environment Variables

```bash
# .env file
DATABASE_URL=postgresql://user:pass@db:5432/gateway
JWT_SECRET=your-production-secret
BIND_ADDRESS=0.0.0.0:8000
CONFIG_FILES=config/users.toml,config/projects.toml,config/tasks.toml
```

### 2. Docker Deployment

```dockerfile
# Dockerfile already exists in project
docker build -t api-gateway .
docker run -p 8000:8000 --env-file .env api-gateway
```

### 3. Health Check

```bash
# Simple health check
curl http://localhost:8000/admin/cache/stats
```

## การ Monitor Production

### 1. Cache Performance

```bash
# Script to monitor cache hit ratio
#!/bin/bash
while true; do
  curl -s http://localhost:8000/admin/cache/stats | jq '.'
  sleep 30
done
```

### 2. Log Analysis

```bash
# Count cache hits vs misses
grep "cache_hit=true" app.log | wc -l
grep "cache_hit=false" app.log | wc -l

# Average response time
grep "Completed role collection" app.log | \
  awk '{print $NF}' | \
  awk '{sum+=$1; count++} END {print "Average:", sum/count "ms"}'
```

## Troubleshooting

### 1. Cache ไม่ทำงาน

```bash
# Check if cache is being used
curl http://localhost:8000/admin/cache/stats

# Clear cache if needed
curl -X DELETE http://localhost:8000/admin/cache
```

### 2. Performance ยังช้า

1. ตรวจสอบ database connection pool
2. ดู cache hit ratio
3. เช็ค network latency
4. Monitor database query performance

### 3. Memory Usage สูง

```bash
# Clear expired entries
curl -X DELETE http://localhost:8000/admin/cache

# หรือ restart service เพื่อ clear cache
```

## Best Practices

1. **Cache Invalidation**: Clear cache เมื่อมีการเปลี่ยน user roles
2. **Monitoring**: ติดตาม cache hit ratio และ response time
3. **Capacity Planning**: ประมาณ 1KB per cached user
4. **Security**: ใช้ HTTPS ใน production
5. **Backup**: Cache เป็น temporary data, ไม่ต้อง backup