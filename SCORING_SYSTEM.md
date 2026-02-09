# 📐 HỆ THỐNG TÍNH ĐIỂM - OWASP CRS-INSPIRED

## 🎯 Công thức tổng quát

```
Total Anomaly Score = Σ(Attack Scores) + Multi-Vector Bonus
```

## 📊 Chi tiết tính điểm cho mỗi Attack Type

### 1. **Pattern Severity Score**
Mỗi pattern được gán độ ưu tiên dựa trên vị trí trong danh sách (patterns quan trọng hơn đặt ở đầu):

| Position | Severity | Score |
|----------|----------|-------|
| Top 20% patterns | HIGH | 4 points |
| 20-50% patterns | MEDIUM | 3 points |
| 50%+ patterns | LOW | 2 points |

**Ý nghĩa**: Patterns quan trọng (SQLi UNION, Command Injection trực tiếp) được ưu tiên hơn patterns ít nguy hiểm (từ khóa đơn lẻ).

### 2. **Diminishing Returns**
Mỗi pattern bổ sung chỉ đóng góp giảm dần để tránh tính điểm quá cao khi nhiều patterns overlap:

```python
pattern_contribution = severity_score × 0.7^(N-1)
```

Với N = số thứ tự pattern match

**Ví dụ**:
- Pattern 1: 4 × 0.7^0 = 4.00 points
- Pattern 2: 4 × 0.7^1 = 2.80 points  
- Pattern 3: 3 × 0.7^2 = 1.47 points
- Pattern 4: 2 × 0.7^3 = 0.69 points

**Tổng**: 8.96 points

### 3. **Complexity Bonus**
Nếu match ≥ 3 patterns khác nhau (indicator của attack phức tạp):

```python
complexity_bonus = min(pattern_count × 0.2, 2.0)
```

**Ví dụ**:
- 3 patterns: +0.6 points
- 5 patterns: +1.0 points
- 10+ patterns: +2.0 points (capped)

### 4. **Attack Weight**
Mỗi attack type có weight riêng (hiện tại hầu hết = 1.0):

```python
weighted_score = attack_score × weight
```

### 5. **Multi-Vector Attack Bonus**
Khi phát hiện nhiều loại attack khác nhau cùng lúc (SQL + XSS, Command + Path Traversal...):

```python
multi_vector_bonus = (num_attack_types - 1) × 1.5
```

**Ví dụ**:
- 2 attack types: +1.5 points
- 3 attack types: +3.0 points
- 4 attack types: +4.5 points

## 🎚️ Severity Thresholds

| Total Score | Severity | Decision | Action |
|-------------|----------|----------|--------|
| ≥ 10 | Critical | **BLOCK** | Chặn ngay lập tức |
| ≥ 6 | High | **BLOCK** | Chặn ngay lập tức |
| ≥ 3 | Medium | **REVIEW** | Gửi LLM phân tích |
| < 3 | Low | **MONITOR** | Ghi log, không chặn |
| = 0 | Safe/Info | **ALLOW** | Cho phép |

## 📈 Ví dụ thực tế

### Example 1: Simple SQL Injection
```
Payload: id=1 UNION SELECT * FROM users
```

**Breakdown**:
- Pattern 1 (UNION SELECT): 4 points
- Pattern 2 (SELECT FROM): 4 × 0.7 = 2.8 points
- **Total**: 6.8 points → **High → BLOCK** ✅

### Example 2: Complex SQL Injection
```
Payload: id=1' UNION ALL SELECT user,password FROM information_schema.tables WHERE '1'='1
```

**Breakdown**:
- Pattern 1: 4.0 points
- Pattern 2: 2.8 points  
- Pattern 3: 1.96 points (diminishing)
- Complexity bonus (3 patterns): +0.6 points
- **Total**: 6.98 points → **High → BLOCK** ✅

### Example 3: Multi-Vector Attack
```
Payload: id=1'; DROP TABLE users; --' && cat /etc/passwd
```

**Breakdown**:
- SQL Injection: 5.4 points (2 patterns)
- Command Injection: 4.0 points (1 pattern)
- Directory Traversal: 3.23 points (2 patterns)
- Multi-vector bonus (3 types): +3.0 points
- **Total**: 15.63 points → **Critical → BLOCK** ✅

### Example 4: Advanced XSS
```
Payload: <script>alert(1)</script><img src=x onerror=window.location='http://evil.com'>
```

**Breakdown**:
- Pattern 1 (script tag): 4.0 points
- Pattern 2 (onerror handler): 2.8 points
- Pattern 3 (window.location): 1.96 points
- Pattern 4 (document.): 1.37 points
- Pattern 5: 0.96 points
- Pattern 6: 0.67 points
- Complexity bonus (6 patterns): +1.2 points
- **Total**: 11.42 points → **Critical → BLOCK** ✅

### Example 5: Benign Query
```
Payload: select * from products where category='electronics'
```

**Breakdown**:
- Pattern 1 (SELECT FROM): 4.0 points
- **Total**: 4.0 points → **Medium → REVIEW** ⚠️

**Note**: Đúng là REVIEW (không BLOCK) vì chỉ 1 pattern, cần LLM xác nhận context.

### Example 6: XXE + File Inclusion Combo
```
Payload: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
```

**Breakdown**:
- Command Injection: 3.0 points
- Directory Traversal: 3.23 points
- Local File Inclusion: 3.8 points
- XML External Entity: 8.41 points
- Multi-vector bonus (4 types): +4.5 points
- **Total**: 27.29 points → **Critical → BLOCK** 🔥

## ✅ Lợi ích của hệ thống mới

1. **Chính xác hơn**: Không chỉ đếm số lượng matches mà đánh giá severity
2. **Giảm False Positives**: Diminishing returns tránh over-scoring
3. **Detect Advanced Attacks**: Multi-vector bonus bắt compound attacks
4. **Context-Aware**: Patterns quan trọng được weighted cao hơn
5. **OWASP CRS Compatible**: Dựa trên chuẩn industry standard
6. **Explainable**: Có thể trace từng thành phần điểm

## 📚 Tham khảo

- [OWASP ModSecurity Core Rule Set](https://coreruleset.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- Anomaly Scoring Mode: https://coreruleset.org/docs/concepts/anomaly_scoring/

---
**Version**: 2.0  
**Last Updated**: February 9, 2026  
**Author**: SOC LangGraph Team
