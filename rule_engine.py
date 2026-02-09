import re
import urllib.parse
from typing import Dict, List


# =====================================================
# SAFE FAST-ALLOW (GIá»® Ráº¤T Háº¸P)
# =====================================================
SAFE_PATTERNS = [
    r"^hello(\s+world)?$",
    r"^hi$",
    r"^test$",
    r"^ping$",
]


# =====================================================
# NORMALIZATION (ENHANCED)
# =====================================================
def normalize(raw: str) -> Dict[str, str]:
    raw_original = raw or ""

    # URL decode up to 3 times (handle nested encoding)
    decoded = raw_original
    for _ in range(3):
        prev = decoded
        decoded = urllib.parse.unquote_plus(decoded)
        if decoded == prev:
            break

    # IIS %uXXXX Unicode encoding
    def decode_u(match):
        try:
            return chr(int(match.group(1), 16))
        except Exception:
            return match.group(0)
    decoded = re.sub(r"%u([0-9a-fA-F]{4})", decode_u, decoded)

    # HTML entities decode (&#x hex and &#decimal)
    decoded = re.sub(r"&#x([0-9a-fA-F]+);", lambda m: chr(int(m.group(1), 16)), decoded)
    decoded = re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1))), decoded)

    # Unicode escape sequences
    decoded = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), decoded)
    decoded = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), decoded)

    lower = decoded.lower()

    # Strip various comment styles
    cleaned = re.sub(r"/\*!?[^*/]*\*/", " ", lower)  # SQL comments
    cleaned = re.sub(r"--[^\r\n]*", " ", cleaned)     # SQL line comments
    cleaned = re.sub(r"#[^\r\n]*", " ", cleaned)      # Hash comments
    cleaned = re.sub(r"//[^\r\n]*", " ", cleaned)     # C-style comments
    
    # Remove null bytes and control chars
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", cleaned)
    
    # Normalize whitespace (including tabs, newlines)
    cleaned = re.sub(r"[\s\r\n\t]+", " ", cleaned).strip()

    return {
        "raw_original": raw_original,
        "raw_decoded": decoded,
        "raw_lower": lower,
        "raw_cleaned": cleaned,
    }


# =====================================================
# SCORING SYSTEM (OWASP CRS ANOMALY SCORING)
# =====================================================
# Exact OWASP ModSecurity CRS severity scores
# Reference: https://coreruleset.org/docs/concepts/anomaly_scoring/

SEVERITY_SCORES = {
    "CRITICAL": 5,  # Critical rules (SQLi, RCE, etc.)
    "ERROR": 4,     # High severity attacks
    "WARNING": 3,   # Medium severity attacks  
    "NOTICE": 2,    # Low severity / recon attempts
}

# OWASP CRS Inbound Anomaly Score Thresholds
# Default CRS thresholds
PARANOIA_THRESHOLDS = {
    "PARANOIA_1": 5,   # Default (balanced security)
    "PARANOIA_2": 7,   # Stricter
    "PARANOIA_3": 10,  # Very strict
    "PARANOIA_4": 15,  # Maximum security
}

# Current threshold (configurable)
INBOUND_ANOMALY_THRESHOLD = PARANOIA_THRESHOLDS["PARANOIA_1"]

# =====================================================
# PATTERN LIBRARY (OWASP CRS STYLE)
# Each pattern has explicit severity for anomaly scoring
# =====================================================
PATTERNS = {
    "SQL Injection": {
        "patterns": [
            # CRITICAL severity - Direct SQLi indicators
            {"regex": r"\bunion\s+(all\s+)?select\b", "severity": "CRITICAL"},
            {"regex": r"\bselect\s+\*\s+from\b", "severity": "CRITICAL"},
            {"regex": r"\b(waitfor\s+delay|sleep\(|benchmark\(|pg_sleep\()", "severity": "CRITICAL"},
            {"regex": r"\b(exec|execute|xp_cmdshell|sp_executesql)", "severity": "CRITICAL"},
            {"regex": r"\binto\s+(outfile|dumpfile)\b", "severity": "CRITICAL"},
            {"regex": r"\binformation_schema\.(tables|columns)", "severity": "CRITICAL"},
            
            # ERROR severity - High confidence SQLi
            {"regex": r"\bselect\s+(@@version|version\(\)|database\(\)|user\(\))", "severity": "ERROR"},
            {"regex": r"\b(insert|update|delete|drop|create|alter|truncate)\s+", "severity": "ERROR"},
            {"regex": r"/\*!?\d{0,5}[^*/]*(select|union|update|delete|insert|drop|alter)", "severity": "ERROR"},
            {"regex": r";\s*(select|insert|update|delete|drop)", "severity": "ERROR"},
            {"regex": r"\bmysql\.(user|db)\b", "severity": "ERROR"},
            
            # WARNING severity - Medium confidence
            {"regex": r"\b(and|or)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?", "severity": "WARNING"},
            {"regex": r"['\"]?\s+(and|or)\s+['\"]?1['\"]?\s*=\s*['\"]?1", "severity": "WARNING"},
            {"regex": r"\b(concat|group_concat|substring|ascii|hex|char|chr)\s*\(", "severity": "WARNING"},
            {"regex": r"\b(cast|convert|extractvalue|updatexml)\s*\(", "severity": "WARNING"},
            {"regex": r"\border\s+by\s+\d+", "severity": "WARNING"},
            {"regex": r"\blike\s+['\"]%[^'\"]*['\"]", "severity": "WARNING"},
            
            # NOTICE severity - Potential SQLi indicators
            {"regex": r"--[\s\r\n]+", "severity": "NOTICE"},
            {"regex": r"/\*[^*]*\*/", "severity": "NOTICE"},
            {"regex": r"0x[0-9a-f]{2,}", "severity": "NOTICE"},
            {"regex": r"char\(\d+\)", "severity": "NOTICE"},
        ],
    },
    
    "Cross-Site Scripting": {
        "patterns": [
            # CRITICAL - Direct XSS execution
            {"regex": r"<\s*script[^>]*>", "severity": "CRITICAL"},
            {"regex": r"javascript\s*:", "severity": "CRITICAL"},
            {"regex": r"\beval\s*\(", "severity": "CRITICAL"},
            {"regex": r"document\.cookie", "severity": "CRITICAL"},
            {"regex": r"window\.location\s*=", "severity": "CRITICAL"},
            
            # ERROR - High confidence XSS
            {"regex": r"<svg[^>]*?on\w+\s*=", "severity": "ERROR"},
            {"regex": r"<iframe[^>]*?(src|srcdoc)", "severity": "ERROR"},
            {"regex": r"\.innerHTML\s*=\s*[^;]+<", "severity": "ERROR"},
            {"regex": r"\bon(load|error|click|focus|blur|change|submit)\s*=", "severity": "ERROR"},
            {"regex": r"<img[^>]*?on\w+\s*=", "severity": "ERROR"},
            
            # WARNING - Medium confidence
            {"regex": r"<embed[^>]*?(src|code)", "severity": "WARNING"},
            {"regex": r"<object[^>]*?(data|type)", "severity": "WARNING"},
            {"regex": r"\bon(mouse|focus|blur|change|submit|key|unload|scroll|wheel)\s*=", "severity": "WARNING"},
            {"regex": r"\b(atob|btoa|settimeout|setinterval|setimmediate)\s*\(", "severity": "WARNING"},
            
            # NOTICE - Low confidence indicators
            {"regex": r"<\s*script[\s/>]", "severity": "NOTICE"},
            {"regex": r"</\s*script\s*>", "severity": "NOTICE"},
            {"regex": r"fromcharcode\s*\(", "severity": "NOTICE"},
        ],
    },
    
    "Command Injection": {
        "patterns": [
            # CRITICAL - Direct command execution
            {"regex": r"(;|\||&|&&|\|\|)\s*(bash|sh|powershell|cmd\.exe|cmd|nc|netcat)", "severity": "CRITICAL"},
            {"regex": r"(;|\||&|&&|\|\|)\s*(cat|wget|curl|nc|rm|rmdir)\s+", "severity": "CRITICAL"},
            {"regex": r"/bin/(ba)?sh\s+(-i|-c|\$)", "severity": "CRITICAL"},
            {"regex": r">\s*/dev/(tcp|udp)/", "severity": "CRITICAL"},
            
            # ERROR - High confidence
            {"regex": r"(;|\||&|&&|\|\|)\s*(id|whoami|uname|pwd|ls|dir)", "severity": "ERROR"},
            {"regex": r"`[^`]{1,100}`", "severity": "ERROR"},
            {"regex": r"\$\([^)]{1,100}\)", "severity": "ERROR"},
            {"regex": r">\s*/tmp/", "severity": "ERROR"},
            
            # WARNING - Medium confidence
            {"regex": r"\b(ping|nslookup|dig|host|tracert|traceroute)\b", "severity": "WARNING"},
            {"regex": r"\b(invoke-expression|iex|invoke-command|powershell)\b", "severity": "WARNING"},
            
            # NOTICE - Potential indicators
            {"regex": r"\$\{[^}]+\}", "severity": "NOTICE"},
            {"regex": r"2>&1|1>&2", "severity": "NOTICE"},
        ],
    },
    
    "Directory Traversal": {
        "patterns": [
            # CRITICAL - Obvious traversal
            {"regex": r"(\.\./|\.\.\\){3,}", "severity": "CRITICAL"},
            {"regex": r"(/etc/passwd|/etc/shadow)", "severity": "CRITICAL"},
            {"regex": r"\.\.%2f\.\.%2f\.\.%2f", "severity": "CRITICAL"},
            
            # ERROR - High confidence
            {"regex": r"\.\./.*\.\./", "severity": "ERROR"},
            {"regex": r"%2e%2e[/%5c]", "severity": "ERROR"},
            {"regex": r"(/etc|/usr|/var|/bin)/(passwd|shadow|hosts)", "severity": "ERROR"},
            
            # WARNING - Medium confidence
            {"regex": r"\b(php\.ini|httpd\.conf|nginx\.conf|web\.config)", "severity": "WARNING"},
            {"regex": r"\.git[/\\](config|HEAD)", "severity": "WARNING"},
            {"regex": r"\.env([\.][a-z]+)?$", "severity": "WARNING"},
            
            # NOTICE - Low confidence
            {"regex": r"\.\./", "severity": "NOTICE"},
            {"regex": r"\.\.\\", "severity": "NOTICE"},
        ],
    },
    
    "Local File Inclusion": {
        "patterns": [
            # CRITICAL - Direct wrapper abuse
            {"regex": r"\bphp://filter[^&\s]*?resource=", "severity": "CRITICAL"},
            {"regex": r"\bdata://text/plain", "severity": "CRITICAL"},
            {"regex": r"\bexpect://", "severity": "CRITICAL"},
            {"regex": r"\b(ftp|ftps|sftp)://.*\.(php|txt|conf)", "severity": "CRITICAL"},
            
            # ERROR - High confidence wrappers
            {"regex": r"\b(php://input|php://stdin)", "severity": "ERROR"},
            {"regex": r"\b(file://|phar://)", "severity": "ERROR"},
            {"regex": r"\bhttps?://[^\s]+\.(php|txt|jsp|asp|jspx)", "severity": "ERROR"},
            
            # WARNING - Potential LFI
            {"regex": r"\b(zip|rar|compress\.zlib)://", "severity": "WARNING"},
            {"regex": r"\bglobaltream://", "severity": "WARNING"},
            
            # NOTICE - Suspicious patterns
            {"regex": r"\.phtml|\.phar|\.shtml", "severity": "NOTICE"},
        ],
    },
    
    "Server-Side Request Forgery": {
        "patterns": [
            # CRITICAL - Cloud metadata endpoints
            {"regex": r"169\.254\.169\.254", "severity": "CRITICAL"},
            {"regex": r"metadata\.google\.internal", "severity": "CRITICAL"},
            
            # ERROR - High confidence
            {"regex": r"https?://127\.0\.0\.1", "severity": "ERROR"},
            {"regex": r"https?://localhost", "severity": "ERROR"},
            {"regex": r"\b(gopher|dict|file)://", "severity": "ERROR"},
            
            # WARNING - Potential SSRF
            {"regex": r"https?://(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.", "severity": "WARNING"},
            {"regex": r"https?://0\.0\.0\.0", "severity": "WARNING"},
            
            # NOTICE - Suspicious URLs
            {"regex": r"https?://https?://", "severity": "NOTICE"},
        ],
    },
    
    "Log Injection": {
        "patterns": [
            # CRITICAL - Log injection vectors
            {"regex": r"\x1b\[[\d;]*[a-zA-Z]", "severity": "CRITICAL"},  # ANSI escape codes
            {"regex": r"[\r\n][\s]*(?:admin|root|error|failed|success)", "severity": "CRITICAL"},  # Log hijacking
            
            # ERROR - Control characters
            {"regex": r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "severity": "ERROR"},  # Control chars
            {"regex": r"[\r\n][\s]*(?:INFO|WARN|ERROR|DEBUG|CRITICAL):", "severity": "ERROR"},  # Fake log lines
            
            # WARNING - Suspicious escapes
            {"regex": r"\\[tnrfvb]", "severity": "WARNING"},  # Escape sequences
            {"regex": r"[\r\n](?![\s]*$)", "severity": "WARNING"},  # Unexpected newlines
        ],
    },
    
    "Cross-Site Request Forgery": {
        "patterns": [
            # CSRF token patterns and bypass attempts
            {"regex": r"csrf\s*=\s*['\"]?[a-f0-9]{32,}", "severity": "WARNING"},
            {"regex": r"_token\s*=\s*['\"]?[a-f0-9]{20,}", "severity": "WARNING"},
            {"regex": r"authenticity_token", "severity": "NOTICE"},
        ],
    },
    
    "CRLF Injection": {
        "patterns": [
            # CRITICAL - Line feed injection
            {"regex": r"%0d%0a|%0a%0d|\r\n|\r|\n", "severity": "CRITICAL"},
            {"regex": r"\\r\\n|\\n\\r", "severity": "ERROR"},
            {"regex": r"[\r\n](?:Location|Set-Cookie|Content-Length):", "severity": "ERROR"},
            
            # WARNING - HTTP header like injections
            {"regex": r"[\r\n]{2,}[\w-]+:\s*", "severity": "WARNING"},
        ],
    },
    
    "HTML Injection": {
        "patterns": [
            # CRITICAL - Direct HTML tags
            {"regex": r"<(html|body|div|p|span|h[1-6]|table|form|input|button)[^>]*>", "severity": "CRITICAL"},
            {"regex": r"<!doctype|<meta|<title|<link", "severity": "CRITICAL"},
            
            # ERROR - DOM manipulation
            {"regex": r"innerHTML|outerhtml|innertext", "severity": "ERROR"},
            
            # WARNING - HTML entities
            {"regex": r"&#\d{2,}|&[a-z]{2,}?;", "severity": "WARNING"},
        ],
    },
    
    "LDAP Injection": {
        "patterns": [
            # CRITICAL - LDAP filter injection
            {"regex": r"\(\|.*\(|\\28\\7c|\\2a", "severity": "CRITICAL"},
            {"regex": r"objectclass=\*|cn=\*|\(\*\)", "severity": "CRITICAL"},
            
            # ERROR - Wildcard patterns
            {"regex": r"\*\|\(|\|\*\(|\*\&\(", "severity": "ERROR"},
            
            # WARNING - LDAP function calls
            {"regex": r"\b(ldap_|ldap:)", "severity": "WARNING"},
        ],
    },
    
    "NoSQL Injection": {
        "patterns": [
            # CRITICAL - MongoDB operators
            {"regex": r"\$\s*(where|regex|function)", "severity": "CRITICAL"},
            {"regex": r"\{\s*['\"]?\$\w+", "severity": "CRITICAL"},
            {"regex": r"db\..*\.find\(", "severity": "CRITICAL"},
            
            # ERROR - High confidence
            {"regex": r"\$where\s*:", "severity": "ERROR"},
            {"regex": r"\{\s*['\"]?[a-z_]+['\"]?\s*:\s*\{", "severity": "ERROR"},
            
            # WARNING - Potential NoSQL
            {"regex": r"\.find\(|\.findOne\(|\.aggregate\(", "severity": "WARNING"},
        ],
    },
    
    "Open Redirect": {
        "patterns": [
            # CRITICAL - External domain redirects
            {"regex": r"(redirect|location|goto|url|link|return_url|return_to|next|returnto|redirect_uri)=https?://", "severity": "CRITICAL"},
            {"regex": r"//[a-z0-9-]+\.[a-z]{2,}", "severity": "CRITICAL"},
            {"regex": r"https?://[a-z0-9-]+\.(com|org|net|io|co|gov)", "severity": "CRITICAL"},
            
            # ERROR - Suspicious redirects
            {"regex": r"javascript:|data:|vbscript:", "severity": "ERROR"},
            
            # WARNING - Potential vectors
            {"regex": r"redirect(\w+)=|location(\w+)=", "severity": "WARNING"},
        ],
    },
    
    "Server-Side Template Injection": {
        "patterns": [
            # CRITICAL - Template expression injection
            {"regex": r"\{\{.*\}\}|\{\%.*\%\}", "severity": "CRITICAL"},
            {"regex": r"\$\{.*\}|#\{.*\}", "severity": "CRITICAL"},
            {"regex": r"<\?=.*\?>|<\?php.*\?>", "severity": "CRITICAL"},
            
            # ERROR - Template functions
            {"regex": r"\b(eval|exec|system|passthru|shell_exec|include|require)\s*\(", "severity": "ERROR"},
            
            # WARNING - Jinja/Mako/Freemarker
            {"regex": r"\bfor\s+.+\s+in\s+|if\s+.+\s+then|extends|import", "severity": "WARNING"},
        ],
    },
    
    "XML External Entity": {
        "patterns": [
            # CRITICAL - XXE vector
            {"regex": r"<!ENTITY\s+\w+\s+SYSTEM", "severity": "CRITICAL"},
            {"regex": r"SYSTEM\s+['\"]file://", "severity": "CRITICAL"},
            
            # ERROR - XXE functions
            {"regex": r"\b(loadxml|parse|simplexml_load)", "severity": "ERROR"},
            
            # WARNING - XML declarations
            {"regex": r"<!DOCTYPE|<!ELEMENT|SYSTEM|PUBLIC", "severity": "WARNING"},
        ],
    },
    
    "Web Cache Deception": {
        "patterns": [
            # Indicators of cache manipulation attempts
            {"regex": r"cache[\s-]?(control|expires|key|bypass)", "severity": "WARNING"},
            {"regex": r"if[-\s]modified[-\s]since|etag|pragma", "severity": "WARNING"},
            {"regex": r"x-original-url|x-rewrite-url|x-forwarded", "severity": "NOTICE"},
        ],
    },
    
    "Information Disclosure": {
        "patterns": [
            # Sensitive path/file patterns
            {"regex": r"\.env|\.git|\.sql", "severity": "ERROR"},
            {"regex": r"backup|config|debug", "severity": "WARNING"},
            {"regex": r"error|exception|traceback", "severity": "NOTICE"},
        ],
    },
}



# =====================================================
# MAIN RULE ENGINE (OWASP CRS ANOMALY SCORING)
# =====================================================
def analyze_request(raw: str) -> dict:
    text = raw.strip().lower()

    # FAST ALLOW - Benign patterns
    for p in SAFE_PATTERNS:
        if re.fullmatch(p, text):
            return {
                "attack_type": "Normal",
                "rule_score": 0.0,
                "severity": "Safe",
                "fast_decision": "ALLOW",
                "evidence": ["safe_pattern"],
                "attack_candidates": [],
            }

    # Normalize vá»›i nhiá»u techniques
    norm = normalize(raw)
    lower = norm["raw_lower"]
    cleaned = norm["raw_cleaned"]
    decoded = norm["raw_decoded"]

    # OWASP CRS Anomaly Scoring
    inbound_anomaly_score = 0
    matched_rules = []
    candidates = []

    # Scan qua táº¥t cáº£ patterns
    for attack_type, config in PATTERNS.items():
        attack_score = 0
        attack_matches = []
        
        # Support new format (with severity per pattern)
        if "patterns" in config:
            for pattern_obj in config["patterns"]:
                regex = pattern_obj["regex"]
                severity = pattern_obj["severity"]
                severity_score = SEVERITY_SCORES[severity]
                
                rxc = re.compile(regex, re.I | re.S)
                
                # Check all normalized forms
                if (rxc.search(lower) or rxc.search(cleaned) or rxc.search(decoded)):
                    # OWASP CRS: Add severity score once per matched rule
                    attack_score += severity_score
                    inbound_anomaly_score += severity_score
                    attack_matches.append({
                        "regex": regex[:50],
                        "severity": severity,
                        "score": severity_score
                    })
        
        # Record if this attack type matched
        if attack_matches:
            candidates.append({
                "type": attack_type,
                "score": round(attack_score, 2),
                "rule_matches": len(attack_matches),
                "evidence": attack_matches[:3]
            })
            matched_rules.extend(attack_matches)

    # No matches found - escalate to LLM for analysis
    if not candidates:
        return {
            "attack_type": "Unknown",
            "rule_score": 0.0,
            "inbound_anomaly_score": 0,
            "severity": "Info",
            "fast_decision": "REVIEW",  # Escalate unknown patterns to LLM
            "evidence": ["no_pattern_match"],
            "attack_candidates": [],
            "requires_llm": True,
        }

    # Determine best attack type (highest score)
    best_candidate = max(candidates, key=lambda x: x["score"])
    best_type = best_candidate["type"]

    # OWASP CRS Decision Logic
    # Compare inbound_anomaly_score against threshold
    if inbound_anomaly_score >= INBOUND_ANOMALY_THRESHOLD:
        decision = "BLOCK"
        
        # Severity based on how much over threshold
        if inbound_anomaly_score >= 15:
            severity = "Critical"
        elif inbound_anomaly_score >= 10:
            severity = "High"
        elif inbound_anomaly_score >= INBOUND_ANOMALY_THRESHOLD:
            severity = "High"
        else:
            severity = "Medium"
    else:
        # Below threshold but suspicious
        if inbound_anomaly_score >= 3:
            decision = "REVIEW"  # Close to threshold, needs analysis
            severity = "Medium"
        else:
            decision = "MONITOR"  # Low score, just log
            severity = "Low"
    
    return {
        "attack_type": best_type,
        "rule_score": round(inbound_anomaly_score, 2),
        "inbound_anomaly_score": round(inbound_anomaly_score, 2),
        "threshold": INBOUND_ANOMALY_THRESHOLD,
        "severity": severity,
        "fast_decision": decision,
        "evidence": [c["type"] for c in candidates[:3]],
        "attack_candidates": candidates,
        "matched_rules_count": len(matched_rules),
    }

