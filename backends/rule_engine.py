import re
import urllib.parse
from typing import Dict, List


# =====================================================
# SAFE FAST-ALLOW (EXACT MATCH - very narrow)
# =====================================================
SAFE_PATTERNS = [
    r"^hello(\s+world)?$",
    r"^hi$",
    r"^test$",
    r"^ping$",
]


# =====================================================
# NORMAL HTTP REQUEST PATTERNS (FAST-ALLOW)
# Matches typical benign HTTP requests to skip LLM call
# =====================================================
NORMAL_REQUEST_PATTERNS = [
    # Standard GET with clean path (no suspicious chars)
    r"^(GET|HEAD|OPTIONS)\s+/[a-zA-Z0-9/_\-\.~%+]*(\?[a-zA-Z0-9=&_\-\.~%+,\[\]@:!$'()*;]*)?(\s+HTTP/[12]\.[01])?",

    # Standard static asset requests
    r"^(GET|HEAD)\s+/[a-zA-Z0-9/_\-\.]+\.(html?|css|js|jsx|ts|tsx|json|xml|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|pdf|txt|csv|map)\b",

    # API endpoints with typical RESTful patterns
    r"^(GET|POST|PUT|PATCH|DELETE)\s+/api/v?[0-9]*/[a-zA-Z0-9/_\-]+(\?[a-zA-Z0-9=&_\-\.%+]*)?(\s+HTTP/[12]\.[01])?",

    # Health check / metrics endpoints
    r"^(GET|HEAD)\s+/(health|healthz|ping|ready|readyz|live|livez|metrics|status|favicon\.ico)(\?.*)?(\s+HTTP/[12]\.[01])?",
]

# Pre-compile normal patterns
_NORMAL_COMPILED = [re.compile(p, re.I) for p in NORMAL_REQUEST_PATTERNS]


def is_normal_request(raw: str) -> bool:
    """
    Fast-allow check: returns True if the request matches known-benign patterns
    AND does not contain any suspicious characters/keywords.
    Both conditions must hold to avoid bypassing attack detection.
    """
    # Extract first line (request line) for pattern matching
    first_line = raw.strip().split("\n")[0].strip()

    # Must match a normal pattern on the first line
    matched_normal = any(p.match(first_line) for p in _NORMAL_COMPILED)
    if not matched_normal:
        return False

    # Even if first line looks normal, reject if body/headers contain suspicious chars.
    # Check both raw (for encoded payloads like %0d%0a) and lowercased forms.
    SUSPICIOUS_QUICK = [
        r"<\s*script",                  # XSS
        r"javascript\s*:",              # XSS
        r"\bunion\s+select\b",          # SQLi
        r"\bselect\s+.*\bfrom\b",       # SQLi
        r"(\.\./){2,}",                 # Path traversal
        r"%2e%2e[/%5c]",                # Encoded traversal
        r"(;|\|)\s*(bash|sh|cmd|powershell|nc\b|wget|curl)\b",  # RCE
        r"\$\{[^}]+\}",                 # SSTI / template injection
        r"\{\{.*\}\}",                  # SSTI Jinja
        r"<!entity",                    # XXE
        r"file://",                     # LFI/SSRF
        r"169\.254\.169\.254",          # SSRF cloud metadata
        # CRLF: both literal \r\n and URL-encoded forms
        r"%0[dD]%0[aA]|%0[aA]%0[dD]|%0[dD]|%0[aA]",
        r"(?:=|%3[dD])[^&\s]{0,50}[\r\n]",
        r"(?:\?|&)\w+=(?:[^&]*\+)?\b(?:ping|nslookup|dig|tracert|traceroute|wget|curl|bash|sh|cmd)\b",  # cmd in param
        r"__proto__",                   # Prototype pollution
        r"rO0[A-Za-z0-9+/]{10,}",      # Java deserialization
        r"(?:O|a):\d+:['\"]",           # PHP deserialization
        r"(?:=|%3[dD])[^&\s]*(?:set-cookie|location|content-type)\s*:",  # Header injection in param
        # Credit card number in URL query params
        r"(?:\?|&)(?:ntc|cc|card|cardnum|pan)\s*=\s*\d{13,19}\b",
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        # Password exposed in URL query string
        r"(?:GET|HEAD)[^\n]*\?[^\n]*(?:password|passwd|pwd|pass|secret)\s*=\s*[^&\s]{3,}",
    ]
    lower = raw.lower()
    for pat in SUSPICIOUS_QUICK:
        # Check both raw (catches %0d%0a) and lowercased
        if re.search(pat, raw, re.I | re.S) or re.search(pat, lower, re.I | re.S):
            return False

    return True


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
SEVERITY_SCORES = {
    "CRITICAL": 5,
    "ERROR": 4,
    "WARNING": 3,
    "NOTICE": 2,
}

PARANOIA_THRESHOLDS = {
    "PARANOIA_1": 5,
    "PARANOIA_2": 7,
    "PARANOIA_3": 10,
    "PARANOIA_4": 15,
}

INBOUND_ANOMALY_THRESHOLD = PARANOIA_THRESHOLDS["PARANOIA_1"]


# =====================================================
# PATTERN LIBRARY (OWASP CRS STYLE - ENHANCED)
# =====================================================
PATTERNS = {

    # --------------------------------------------------
    # SQL INJECTION
    # --------------------------------------------------
    "SQL Injection": {
        "patterns": [
            # CRITICAL - Unambiguous SQLi
            {"regex": r"\bunion\s+(all\s+)?select\b", "severity": "CRITICAL"},
            {"regex": r"\bselect\s+\*\s+from\b", "severity": "CRITICAL"},
            {"regex": r"\b(waitfor\s+delay|sleep\s*\(|benchmark\s*\(|pg_sleep\s*\()", "severity": "CRITICAL"},
            {"regex": r"\b(exec\s*\(|execute\s*\(|xp_cmdshell\s*\(|sp_executesql\s*\()", "severity": "CRITICAL"},
            {"regex": r"\binto\s+(outfile|dumpfile)\b", "severity": "CRITICAL"},
            {"regex": r"\binformation_schema\.(tables|columns|schemata)\b", "severity": "CRITICAL"},
            {"regex": r"\bload_file\s*\(", "severity": "CRITICAL"},

            # ERROR - High confidence SQLi
            {"regex": r"\bselect\s+(@@version|version\s*\(\)|database\s*\(\)|user\s*\(\)|schema\s*\(\))", "severity": "ERROR"},
            {"regex": r"\b(drop|truncate)\s+(table|database|schema)\b", "severity": "ERROR"},
            {"regex": r"\b(insert\s+into|update\s+\w+\s+set|delete\s+from)\b", "severity": "ERROR"},
            {"regex": r";\s*(select|insert|update|delete|drop|create|alter|exec)\b", "severity": "ERROR"},
            {"regex": r"\bmysql\.(user|db|tables_priv)\b", "severity": "ERROR"},
            {"regex": r"/\*!?\d{0,5}\s*(select|union|update|delete|insert|drop|alter)\b", "severity": "ERROR"},

            # WARNING - Medium confidence
            {"regex": r"['\"]?\s+\b(and|or)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", "severity": "WARNING"},
            {"regex": r"\b(concat|group_concat|substring|substr|ascii|hex|char|chr|ord)\s*\(", "severity": "WARNING"},
            {"regex": r"\b(cast|convert|extractvalue|updatexml|xmltype)\s*\(", "severity": "WARNING"},
            {"regex": r"\border\s+by\s+\d+\b", "severity": "WARNING"},
            {"regex": r"\bhaving\s+\d+\s*=\s*\d+", "severity": "WARNING"},
            {"regex": r"\b(sys\.tables|sys\.columns|sysobjects|syscolumns)\b", "severity": "WARNING"},

            # NOTICE - Potential indicators
            {"regex": r"0x[0-9a-f]{4,}", "severity": "NOTICE"},
            {"regex": r"\bchar\s*\(\d+", "severity": "NOTICE"},
            {"regex": r"'\s*;\s*--", "severity": "NOTICE"},
        ],
    },

    # --------------------------------------------------
    # CROSS-SITE SCRIPTING (XSS)
    # --------------------------------------------------
    "Cross-Site Scripting": {
        "patterns": [
            # CRITICAL - Direct XSS execution
            {"regex": r"<\s*script[^>]*>", "severity": "CRITICAL"},
            {"regex": r"javascript\s*:", "severity": "CRITICAL"},
            {"regex": r"\beval\s*\(", "severity": "CRITICAL"},
            {"regex": r"document\s*\.\s*cookie", "severity": "CRITICAL"},
            {"regex": r"window\s*\.\s*location\s*=", "severity": "CRITICAL"},
            {"regex": r"document\s*\.\s*write\s*\(", "severity": "CRITICAL"},

            # ERROR - High confidence XSS
            {"regex": r"<\s*svg[^>]*?\bon\w+\s*=", "severity": "ERROR"},
            {"regex": r"<\s*iframe[^>]*(src|srcdoc)\s*=", "severity": "ERROR"},
            {"regex": r"\.innerHTML\s*=", "severity": "ERROR"},
            {"regex": r"\bon(load|error|click|focus|blur|change|submit|mouseover|mouseout)\s*=", "severity": "ERROR"},
            {"regex": r"<\s*img[^>]*?\bon\w+\s*=", "severity": "ERROR"},
            {"regex": r"<\s*body[^>]*?\bon\w+\s*=", "severity": "ERROR"},

            # WARNING - Medium confidence
            {"regex": r"<\s*(embed|object|applet)[^>]*?(src|code|data)\s*=", "severity": "WARNING"},
            {"regex": r"\b(atob|btoa|settimeout|setinterval|setimmediate)\s*\(", "severity": "WARNING"},
            {"regex": r"String\.fromCharCode\s*\(", "severity": "WARNING"},
            {"regex": r"<\s*details[^>]*?\bon\w+\s*=", "severity": "WARNING"},
            {"regex": r"<\s*video[^>]*?\bon\w+\s*=", "severity": "WARNING"},

            # NOTICE - Low confidence
            {"regex": r"</\s*script\s*>", "severity": "NOTICE"},
            {"regex": r"fromcharcode\s*\(", "severity": "NOTICE"},
            {"regex": r"vbscript\s*:", "severity": "NOTICE"},
        ],
    },

    # --------------------------------------------------
    # COMMAND INJECTION / OS INJECTION
    # --------------------------------------------------
    "Command Injection": {
        "patterns": [
            # CRITICAL - Direct RCE
            {"regex": r"(?:;|\||&&|\|\|)\s*(?:bash|sh|zsh|ksh|csh|tcsh|powershell|cmd\.exe|cmd)\b", "severity": "CRITICAL"},
            {"regex": r"(?:;|\||&&|\|\|)\s*(?:wget|curl|nc|netcat|ncat|socat)\s+", "severity": "CRITICAL"},
            {"regex": r"/bin/(?:ba)?sh\s+(?:-i|-c|\$)", "severity": "CRITICAL"},
            {"regex": r">\s*/dev/(?:tcp|udp)/", "severity": "CRITICAL"},
            {"regex": r"\b(?:python|python3|perl|ruby|php|node)\s+-[ce]\s+['\"]", "severity": "CRITICAL"},

            # ERROR - High confidence
            {"regex": r"(?:;|\||&&|\|\|)\s*(?:id|whoami|uname|pwd|ls\s|dir\s|cat\s|type\s)", "severity": "ERROR"},
            {"regex": r"`[^`]{1,200}`", "severity": "ERROR"},
            {"regex": r"\$\([^)]{1,200}\)", "severity": "ERROR"},
            {"regex": r">\s*/tmp/[a-z]", "severity": "ERROR"},
            {"regex": r"\b(?:chmod|chown|chgrp)\s+[0-9o+\-]+\s+/", "severity": "ERROR"},
            {"regex": r"\b(?:curl|wget)\s+https?://[^\s]+\s*\|\s*(?:bash|sh)\b", "severity": "ERROR"},

            # WARNING - Medium confidence (only in param values, not standalone headers)
            {"regex": r"(?:=|%3d)[^&\s]*\b(?:ping|nslookup|dig|tracert|traceroute)\b", "severity": "WARNING"},
            {"regex": r"\b(?:invoke-expression|iex|invoke-command)\b", "severity": "WARNING"},
            {"regex": r"\b(?:system|passthru|shell_exec|popen|proc_open)\s*\(", "severity": "WARNING"},

            # NOTICE - Potential indicators
            {"regex": r"2>&1|1>&2", "severity": "NOTICE"},
            {"regex": r"\|\s*tee\s+/", "severity": "NOTICE"},
        ],
    },

    # --------------------------------------------------
    # DIRECTORY / PATH TRAVERSAL
    # --------------------------------------------------
    "Directory Traversal": {
        "patterns": [
            # CRITICAL - Obvious traversal
            {"regex": r"(?:\.\./|\.\.\\){3,}", "severity": "CRITICAL"},
            {"regex": r"/etc/(?:passwd|shadow|sudoers|hosts|crontab|group)\b", "severity": "CRITICAL"},
            {"regex": r"\.\.%2f\.\.%2f\.\.%2f", "severity": "CRITICAL"},
            {"regex": r"(?:%2e%2e%2f|%2e%2e/|\.\.%2f){2,}", "severity": "CRITICAL"},

            # ERROR - High confidence
            {"regex": r"\.\./.*\.\./", "severity": "ERROR"},
            {"regex": r"%2e%2e[/%5c]", "severity": "ERROR"},
            {"regex": r"/(?:proc|sys)/(?:self|net|version)\b", "severity": "ERROR"},
            {"regex": r"C:\\(?:Windows|Users|Program Files)\\", "severity": "ERROR"},

            # WARNING - Medium confidence
            {"regex": r"\b(?:php\.ini|httpd\.conf|nginx\.conf|web\.config|wp-config\.php)\b", "severity": "WARNING"},
            {"regex": r"\.git[/\\](?:config|HEAD|ORIG_HEAD|packed-refs)\b", "severity": "WARNING"},
            {"regex": r"\.env(?:\.[a-z]+)?(?:\s|$|\")", "severity": "WARNING"},

            # NOTICE - Low confidence
            {"regex": r"\.\./", "severity": "NOTICE"},
            {"regex": r"\.\.\\", "severity": "NOTICE"},
        ],
    },

    # --------------------------------------------------
    # LOCAL FILE INCLUSION (LFI)
    # --------------------------------------------------
    "Local File Inclusion": {
        "patterns": [
            # CRITICAL - PHP wrapper abuse
            {"regex": r"\bphp://filter[^&\s]*?resource=", "severity": "CRITICAL"},
            {"regex": r"\bdata://text/plain", "severity": "CRITICAL"},
            {"regex": r"\bexpect://", "severity": "CRITICAL"},
            {"regex": r"\bphar://[^\s]+\.(?:php|phar)\b", "severity": "CRITICAL"},

            # ERROR - High confidence wrappers
            {"regex": r"\bphp://(?:input|stdin|fd)\b", "severity": "ERROR"},
            {"regex": r"\bfile://(?:/[a-z]|[a-z]:\\)", "severity": "ERROR"},
            {"regex": r"\bzip://[^\s]+#", "severity": "ERROR"},

            # WARNING - Potential LFI
            {"regex": r"\bcompress\.(?:zlib|bzip2)://", "severity": "WARNING"},
            {"regex": r"\b(?:include|require)(?:_once)?\s*\(['\"][^'\"]*\.\.", "severity": "WARNING"},

            # NOTICE - Suspicious extensions
            {"regex": r"\.(?:phtml|phar|shtml|phps)\b", "severity": "NOTICE"},
        ],
    },

    # --------------------------------------------------
    # SERVER-SIDE REQUEST FORGERY (SSRF)
    # --------------------------------------------------
    "Server-Side Request Forgery": {
        "patterns": [
            # CRITICAL - Cloud metadata / internal services
            {"regex": r"169\.254\.169\.254", "severity": "CRITICAL"},
            {"regex": r"metadata\.google\.internal", "severity": "CRITICAL"},
            {"regex": r"fd00:|::1\b", "severity": "CRITICAL"},
            {"regex": r"0177\.0\.0\.1|0x7f000001", "severity": "CRITICAL"},  # Obfuscated 127.0.0.1

            # ERROR - High confidence SSRF
            {"regex": r"https?://127\.0\.0\.1(?::\d+)?/", "severity": "ERROR"},
            {"regex": r"https?://localhost(?::\d+)?/", "severity": "ERROR"},
            {"regex": r"\b(?:gopher|dict|ldap|tftp)://", "severity": "ERROR"},

            # WARNING - Private IP ranges
            {"regex": r"https?://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)", "severity": "WARNING"},
            {"regex": r"https?://0\.0\.0\.0", "severity": "WARNING"},

            # NOTICE - Suspicious URL patterns
            {"regex": r"https?://https?://", "severity": "NOTICE"},
        ],
    },

    # --------------------------------------------------
    # LOG INJECTION
    # --------------------------------------------------
    "Log Injection": {
        "patterns": [
            # CRITICAL - ANSI escape / log hijacking
            {"regex": r"\x1b\[[\d;]*[a-zA-Z]", "severity": "CRITICAL"},
            {"regex": r"[\r\n][\s]*(?:admin|root|error|failed|success|login)\b", "severity": "CRITICAL"},

            # ERROR - Fake log lines / control chars
            {"regex": r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "severity": "ERROR"},
            {"regex": r"[\r\n][\s]*(?:INFO|WARN|ERROR|DEBUG|CRITICAL|FATAL)\s*:", "severity": "ERROR"},

            # WARNING - Newlines in param value followed by log-level keywords
            {"regex": r"(?:\?|&)\w+=[^&]*[\r\n]+\s*(?:INFO|WARN|ERROR|DEBUG|FATAL)\s*:", "severity": "WARNING"},
        ],
    },

    # --------------------------------------------------
    # CRLF INJECTION
    # Avoid matching literal \n between HTTP headers in pasted text
    # Only flag URL-encoded CRLF or CRLF inside parameter values
    # --------------------------------------------------
    "CRLF Injection": {
        "patterns": [
            # CRITICAL - URL-encoded CRLF inside param value followed by HTTP header (response splitting)
            {"regex": r"(?:=|%3[dD])[^&\s]*(?:%0[dD]%0[aA]|%0[aA]%0[dD]|%0[dD]|%0[aA])[^&\s]*(?:set-cookie|location|content-type|content-length|transfer-encoding)\s*(?:%3[aA]|:)", "severity": "CRITICAL"},
            # CRLF decoded to \r\n in param followed by HTTP header keyword
            {"regex": r"(?:\?|&)\w+=[^&]*[\r\n]+\s*(?:set-cookie|location|content-type|content-length|transfer-encoding|x-[\w-]+)\s*:", "severity": "CRITICAL"},

            # ERROR - Literal escaped \r\n followed by header (JSON/log injection)
            {"regex": r"\\r\\n[A-Za-z][\w-]+\s*:", "severity": "ERROR"},

            # WARNING - Double URL-encoded CRLF (response splitting)
            {"regex": r"(?:%0[dD]%0[aA]){2,}", "severity": "WARNING"},
            # Standalone %0d%0a in URL path/param (no header after, but still suspicious)
            {"regex": r"(?:=|%3[dD])[^&\s]*(?:%0[dD]%0[aA]|%0[aA]%0[dD])", "severity": "WARNING"},
        ],
    },

    # --------------------------------------------------
    # HTML INJECTION
    # --------------------------------------------------
    "HTML Injection": {
        "patterns": [
            # CRITICAL - Structural HTML injection
            {"regex": r"<\s*(?:html|body|head|form)[^>]*>", "severity": "CRITICAL"},
            {"regex": r"<!doctype\s+html", "severity": "CRITICAL"},

            # ERROR - DOM manipulation
            {"regex": r"\.innerHTML\s*=|\.outerHTML\s*=|\.insertAdjacentHTML\s*\(", "severity": "ERROR"},
            {"regex": r"<\s*(?:meta|link|base)[^>]*>", "severity": "ERROR"},

            # WARNING - Injected interactive elements
            {"regex": r"<\s*(?:input|button|select|textarea)[^>]*>", "severity": "WARNING"},
            {"regex": r"&#\d{2,5};|&#x[0-9a-f]{2,5};", "severity": "WARNING"},
        ],
    },

    # --------------------------------------------------
    # LDAP INJECTION
    # --------------------------------------------------
    "LDAP Injection": {
        "patterns": [
            # CRITICAL - LDAP filter injection
            {"regex": r"\(\|[^)]*\(|\\28\\7c|\\2a", "severity": "CRITICAL"},
            {"regex": r"\bobjectclass\s*=\s*\*|\bcn\s*=\s*\*|\(\*\)", "severity": "CRITICAL"},

            # ERROR - Wildcard abuse
            {"regex": r"\*\|\(|\|\*\(|\*\&\(", "severity": "ERROR"},

            # WARNING - LDAP function/protocol
            {"regex": r"\bldap[_:]", "severity": "WARNING"},
            {"regex": r"\bou\s*=|dc\s*=|uid\s*=", "severity": "NOTICE"},
        ],
    },

    # --------------------------------------------------
    # NOSQL INJECTION
    # --------------------------------------------------
    "NoSQL Injection": {
        "patterns": [
            # CRITICAL - MongoDB operators
            {"regex": r"\$\s*(?:where|regex|function|ne|gt|lt|gte|lte|in|nin|exists|type)\b", "severity": "CRITICAL"},
            {"regex": r"\{\s*['\"]?\$\w+", "severity": "CRITICAL"},
            {"regex": r"\bdb\s*\.\s*\w+\s*\.\s*find\s*\(", "severity": "CRITICAL"},

            # ERROR - High confidence
            {"regex": r"\$where\s*:", "severity": "ERROR"},
            {"regex": r"\[\s*\$(?:ne|gt|lt|gte|lte|in|nin)\s*\]", "severity": "ERROR"},

            # WARNING - Potential NoSQL
            {"regex": r"\.(?:find|findOne|aggregate|count|distinct)\s*\(", "severity": "WARNING"},
            {"regex": r"mapreduce|group\s*:\s*\{", "severity": "WARNING"},
        ],
    },

    # --------------------------------------------------
    # OPEN REDIRECT
    # --------------------------------------------------
    "Open Redirect": {
        "patterns": [
            # CRITICAL - External domain redirects via common params
            {"regex": r"(?:redirect|location|goto|url|link|return_url|return_to|next|returnto|redirect_uri|continue|target|dest(?:ination)?)\s*=\s*https?://(?!localhost|127\.)", "severity": "CRITICAL"},
            {"regex": r"(?:redirect|location|goto|url|next|target)\s*=\s*//[a-z0-9\-]+\.[a-z]{2,}", "severity": "CRITICAL"},

            # ERROR - Protocol-based redirects
            {"regex": r"(?:redirect|location|goto|url|next)\s*=\s*(?:javascript:|data:|vbscript:)", "severity": "ERROR"},

            # WARNING - Potential bypass techniques
            {"regex": r"(?:redirect|url|next)\s*=\s*[^&\s]*@[a-z0-9\-]+\.[a-z]{2,}", "severity": "WARNING"},
            {"regex": r"(?:redirect|url|next)\s*=\s*///", "severity": "WARNING"},
        ],
    },

    # --------------------------------------------------
    # SERVER-SIDE TEMPLATE INJECTION (SSTI)
    # --------------------------------------------------
    "Server-Side Template Injection": {
        "patterns": [
            # CRITICAL - Template expression injection
            {"regex": r"\{\{[^}]{1,200}\}\}", "severity": "CRITICAL"},   # Jinja2/Twig/Handlebars
            {"regex": r"\{%[^%]{1,200}%\}", "severity": "CRITICAL"},     # Jinja2/Django
            {"regex": r"\$\{[^}]{1,200}\}", "severity": "CRITICAL"},     # FreeMarker/Thymeleaf
            {"regex": r"#\{[^}]{1,200}\}", "severity": "CRITICAL"},      # Ruby ERB / SpEL
            {"regex": r"<\?=.{1,200}\?>|<\?php.{1,200}\?>", "severity": "CRITICAL"},

            # ERROR - Template RCE functions
            {"regex": r"\b(?:__class__|__mro__|__subclasses__|__import__)\b", "severity": "ERROR"},
            {"regex": r"\b(?:config\.items|self\._|request\.application)\b", "severity": "ERROR"},

            # WARNING - Template keywords
            {"regex": r"\b(?:namespace|block|macro|filter|set)\s+\w+", "severity": "WARNING"},
        ],
    },

    # --------------------------------------------------
    # XML EXTERNAL ENTITY (XXE)
    # --------------------------------------------------
    "XML External Entity": {
        "patterns": [
            # CRITICAL - XXE vector
            {"regex": r"<!ENTITY\s+\w+\s+SYSTEM\b", "severity": "CRITICAL"},
            {"regex": r"\bSYSTEM\s+['\"](?:file|http|ftp|expect|php)://", "severity": "CRITICAL"},
            {"regex": r"<!ENTITY\s+%\s*\w+\s+SYSTEM\b", "severity": "CRITICAL"},  # Blind XXE

            # ERROR - XXE functions
            {"regex": r"\b(?:loadxml|simplexml_load_string|simplexml_load_file)\b", "severity": "ERROR"},
            {"regex": r"<!DOCTYPE\s+\w+\s*\[", "severity": "ERROR"},

            # WARNING - XML declarations with word boundaries
            {"regex": r"<!DOCTYPE\b|<!ELEMENT\b|\bSYSTEM\b|\bPUBLIC\b", "severity": "WARNING"},
        ],
    },

    # --------------------------------------------------
    # HTTP REQUEST SMUGGLING
    # --------------------------------------------------
    "HTTP Request Smuggling": {
        "patterns": [
            # CRITICAL - Conflicting Content-Length / Transfer-Encoding
            {"regex": r"Transfer-Encoding\s*:\s*chunked[^\r\n]*[\r\n]+.*Content-Length\s*:", "severity": "CRITICAL"},
            {"regex": r"Content-Length\s*:\s*\d+[^\r\n]*[\r\n]+.*Transfer-Encoding\s*:", "severity": "CRITICAL"},

            # ERROR - Obfuscated Transfer-Encoding
            {"regex": r"Transfer-Encoding\s*:\s*(?:xchunked|chunked\s|[\x09\x20]chunked)", "severity": "ERROR"},
            {"regex": r"Transfer-Encoding\s*:\s*[^\r\n]*,\s*chunked", "severity": "ERROR"},

            # WARNING - Suspicious framing headers
            {"regex": r"Transfer-Encoding\s*:\s*(?!chunked|identity)[^\r\n]+", "severity": "WARNING"},
            {"regex": r"Content-Length\s*:\s*-\d+", "severity": "WARNING"},
        ],
    },

    # --------------------------------------------------
    # PROTOTYPE POLLUTION (JavaScript)
    # --------------------------------------------------
    "Prototype Pollution": {
        "patterns": [
            # CRITICAL - Direct prototype manipulation
            {"regex": r"__proto__\s*[\[.]", "severity": "CRITICAL"},
            {"regex": r"constructor\s*\.\s*prototype\b", "severity": "CRITICAL"},
            {"regex": r"\[['\"]\s*__proto__\s*['\"]\]", "severity": "CRITICAL"},

            # ERROR - High confidence
            {"regex": r"prototype\s*\[", "severity": "ERROR"},
            {"regex": r"__defineGetter__|__defineSetter__|__lookupGetter__", "severity": "ERROR"},

            # WARNING - Potential pollution
            {"regex": r"Object\.assign\s*\(\s*\{\}", "severity": "WARNING"},
            {"regex": r"JSON\.parse\s*\([^)]*__proto__", "severity": "WARNING"},
        ],
    },

    # --------------------------------------------------
    # JWT ATTACK
    # --------------------------------------------------
    "JWT Attack": {
        "patterns": [
            # CRITICAL - Algorithm confusion / none algorithm
            {"regex": r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]*", "severity": "CRITICAL"},  # JWT token in body/param
            {"regex": r'"alg"\s*:\s*"none"', "severity": "CRITICAL"},
            {"regex": r"eyJhbGciOiJub25lIn0", "severity": "CRITICAL"},  # base64 of {"alg":"none"}

            # ERROR - Algorithm downgrade
            {"regex": r'"alg"\s*:\s*"HS(?:256|384|512)"', "severity": "ERROR"},  # HS256 in param (potential RS->HS confusion)

            # WARNING - JWT manipulation indicators
            {"regex": r"\.eyJ[a-zA-Z0-9_\-]{10,}\.", "severity": "WARNING"},
        ],
    },

    # --------------------------------------------------
    # GRAPHQL INJECTION
    # --------------------------------------------------
    "GraphQL Injection": {
        "patterns": [
            # CRITICAL - Introspection / schema dump
            {"regex": r"\b__schema\b|\b__type\b|\b__typename\b", "severity": "CRITICAL"},
            {"regex": r"IntrospectionQuery", "severity": "CRITICAL"},

            # ERROR - Mutation abuse
            {"regex": r"\bmutation\s*\{[^}]*(?:delete|drop|remove|update)\b", "severity": "ERROR"},
            {"regex": r"\bquery\s*\{[^}]*\bpassword\b", "severity": "ERROR"},

            # WARNING - Nested queries (DoS / batching attack)
            {"regex": r"(?:query|mutation)\s*\{[^}]*\{[^}]*\{[^}]*\{", "severity": "WARNING"},
            {"regex": r"\[\s*\{[^}]*query[^}]*\},\s*\{[^}]*query", "severity": "WARNING"},  # Batched queries
        ],
    },

    # --------------------------------------------------
    # INSECURE DESERIALIZATION
    # --------------------------------------------------
    "Insecure Deserialization": {
        "patterns": [
            # CRITICAL - Java serialization magic bytes (base64 encoded rO0)
            {"regex": r"rO0[A-Za-z0-9+/]{10,}", "severity": "CRITICAL"},
            # PHP serialization
            {"regex": r'O:\d+:"[a-zA-Z_][a-zA-Z0-9_]*":\d+:\{', "severity": "CRITICAL"},
            {"regex": r's:\d+:"[^"]{0,200}";', "severity": "ERROR"},

            # ERROR - Python pickle
            {"regex": r"\\x80\\x(?:02|03|04|05)", "severity": "ERROR"},  # Pickle protocol magic

            # WARNING - YAML deserialization gadgets
            {"regex": r"!!python/object(?:/apply)?:", "severity": "WARNING"},
            {"regex": r"!!java\.(?:lang|util|io)\.", "severity": "WARNING"},
            {"regex": r"!!ruby/object:", "severity": "WARNING"},
        ],
    },

    # --------------------------------------------------
    # WEB CACHE DECEPTION
    # --------------------------------------------------
    "Web Cache Deception": {
        "patterns": [
            # Only flag cache headers when injected as parameter values
            {"regex": r"(?:=|%3d)[^&\s]*cache[\s\-]?(?:control|expires|key|bypass)", "severity": "WARNING"},
            {"regex": r"(?:=|%3d)[^&\s]*(?:if[\-\s]modified[\-\s]since|etag|pragma)", "severity": "WARNING"},
            # Header override injection
            {"regex": r"x-original-url\s*:|x-rewrite-url\s*:", "severity": "NOTICE"},
            # Path-based cache deception: real path + static extension
            {"regex": r"/[a-zA-Z0-9_\-]+\.(css|js|jpg|jpeg|png|gif|ico|svg|woff2?)\s*(?:$|\s)", "severity": "WARNING"},
        ],
    },

    # --------------------------------------------------
    # INFORMATION DISCLOSURE
    # --------------------------------------------------
    "Information Disclosure": {
        "patterns": [
            # ERROR - Sensitive files
            {"regex": r"\.env(?:\.[a-z]+)?(?:\s|$|\")", "severity": "ERROR"},
            {"regex": r"\.git(?:/|\\)(?:config|HEAD|log|pack)\b", "severity": "ERROR"},
            {"regex": r"\b(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|\.pem|\.p12|\.pfx)\b", "severity": "ERROR"},
            {"regex": r"\bwp-config\.php\b|\bconfig\.php\b|\bsettings\.py\b", "severity": "ERROR"},

            # WARNING - Backup / debug files
            {"regex": r"\b(?:backup|dump|export)\b.*\.(?:sql|zip|tar|gz|bak|old)\b", "severity": "WARNING"},
            {"regex": r"/(?:phpinfo|info|test|debug)\.php\b", "severity": "WARNING"},
            {"regex": r"\b(?:swagger|openapi|api-docs|graphiql)\b", "severity": "NOTICE"},
        ],
    },

    # --------------------------------------------------
    # CROSS-SITE REQUEST FORGERY (CSRF bypass indicators)
    # --------------------------------------------------
    "Cross-Site Request Forgery": {
        "patterns": [
            # CSRF token manipulation
            {"regex": r"csrf(?:_token|[_\-]?key)?\s*=\s*(?:''|null|undefined|0|false)", "severity": "WARNING"},
            {"regex": r"x-csrf-token\s*:\s*(?:null|undefined|''|0)", "severity": "WARNING"},
            {"regex": r"authenticity_token\s*=\s*[a-f0-9]{32,}", "severity": "NOTICE"},
        ],
    },

    # --------------------------------------------------
    # SERVER-SIDE TEMPLATE INJECTION (SSTI) - already above, skip
    # LDAP - already above
    # --------------------------------------------------

    # --------------------------------------------------
    # BUSINESS LOGIC / PARAMETER TAMPERING
    # --------------------------------------------------
    "Parameter Tampering": {
        "patterns": [
            # Negative price / quantity
            {"regex": r"(?:price|amount|qty|quantity|total|cost)\s*=\s*-\d+", "severity": "WARNING"},
            # Mass assignment attempts
            {"regex": r"(?:admin|is_admin|role|privilege|permission)\s*=\s*(?:1|true|admin|superuser)", "severity": "WARNING"},
            # Account takeover via parameter
            {"regex": r"(?:user_?id|account_?id|uid)\s*=\s*\d+", "severity": "NOTICE"},
        ],
    },

    # --------------------------------------------------
    # SENSITIVE DATA EXPOSURE
    # Detect credit card numbers, SSN, passwords in plaintext
    # --------------------------------------------------
    "Sensitive Data Exposure": {
        "patterns": [
            # CRITICAL - Credit card number patterns (Luhn-compatible length, major brands)
            # Visa: 4xxx xxxx xxxx xxxx, MC: 5xxx, Amex: 3xxx (15 digits), Discover: 6xxx
            {"regex": r"(?:^|[=&\s])(?:ntc|cc|card|cardnumber|card_?num(?:ber)?|pan|cvv|ccnum)\s*=\s*\d{13,19}\b", "severity": "CRITICAL"},
            # Raw 16-digit card number in body (groups of 4 or continuous)
            {"regex": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", "severity": "CRITICAL"},

            # ERROR - SSN / national ID patterns
            {"regex": r"\b\d{3}-\d{2}-\d{4}\b", "severity": "ERROR"},  # US SSN
            {"regex": r"\b[0-9]{8}[A-Z]\b", "severity": "ERROR"},       # Spanish DNI (e.g. 41944516Z)

            # WARNING - Password field exposed in URL query string (GET request)
            # Only flag when preceded by ? (query string start), not & in POST body
            {"regex": r"(?:GET|HEAD)[^\n]*\?[^\n]*(?:password|passwd|pwd|pass|secret)\s*=\s*[^&\s]{3,}", "severity": "WARNING"},

            # NOTICE - Suspicious disposable/free email domains used in fraud
            {"regex": r"@(?:mailinator|guerrillamail|tempmail|throwam|yopmail|sharklasers|trashmail|dispostable|maildrop|fakeinbox|spamgourmet|getairmail|discard\.email)\.", "severity": "NOTICE"},
        ],
    },

    # --------------------------------------------------
    # ACCOUNT FRAUD / CARDING
    # Business logic attacks targeting registration/payment
    # --------------------------------------------------
    "Account Fraud": {
        "patterns": [
            # CRITICAL - Card testing: multiple card fields together
            {"regex": r"(?:ntc|cc|cardnum|card_number)\s*=\s*\d{13,19}[^&]*&[^&]*(?:cvv|cvc|cvv2|securitycode)\s*=\s*\d{3,4}", "severity": "CRITICAL"},
            # Card number with expiry
            {"regex": r"(?:ntc|cc|cardnum)\s*=\s*\d{13,19}[^&]*&[^&]*(?:exp|expiry|expdate|exp_month|exp_year)\s*=", "severity": "CRITICAL"},

            # ERROR - Suspicious TLD in email for registration endpoints
            {"regex": r"(?:registro|register|signup|account|user)[^&]*email\s*=\s*[^&@]+@[^&\s]+\.(?:pw|tk|ml|ga|cf|gq|xyz|top|click|loan|win|bid|date|racing|download)\b", "severity": "ERROR"},

            # WARNING - Credential stuffing indicators
            {"regex": r"(?:login|username|user)\s*=\s*(?:admin|root|administrator|test|guest|user1|demo)\b", "severity": "WARNING"},
        ],
    },
}


# =====================================================
# MAIN RULE ENGINE (OWASP CRS ANOMALY SCORING)
# =====================================================
def analyze_request(raw: str) -> dict:
    text = raw.strip().lower()

    # FAST ALLOW - Exact match benign patterns
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

    # FAST ALLOW - Normal HTTP request heuristic
    if is_normal_request(raw):
        return {
            "attack_type": "Normal",
            "rule_score": 0.0,
            "severity": "Info",
            "fast_decision": "ALLOW",
            "evidence": ["normal_http_request"],
            "attack_candidates": [],
        }

    # Normalize with multiple techniques
    norm = normalize(raw)
    lower = norm["raw_lower"]
    cleaned = norm["raw_cleaned"]
    decoded = norm["raw_decoded"]

    # OWASP CRS Anomaly Scoring
    inbound_anomaly_score = 0
    matched_rules = []
    candidates = []

    for attack_type, config in PATTERNS.items():
        attack_score = 0
        attack_matches = []

        if "patterns" in config:
            for pattern_obj in config["patterns"]:
                regex = pattern_obj["regex"]
                severity = pattern_obj["severity"]
                severity_score = SEVERITY_SCORES[severity]

                rxc = re.compile(regex, re.I | re.S)

                if rxc.search(lower) or rxc.search(cleaned) or rxc.search(decoded):
                    attack_score += severity_score
                    inbound_anomaly_score += severity_score
                    attack_matches.append({
                        "regex": regex[:60],
                        "severity": severity,
                        "score": severity_score
                    })

        if attack_matches:
            candidates.append({
                "type": attack_type,
                "score": round(attack_score, 2),
                "rule_matches": len(attack_matches),
                "evidence": attack_matches[:3]
            })
            matched_rules.extend(attack_matches)

    # No matches - escalate to LLM
    if not candidates:
        return {
            "attack_type": "Unknown",
            "rule_score": 0.0,
            "inbound_anomaly_score": 0,
            "severity": "Info",
            "fast_decision": "REVIEW",
            "evidence": ["no_pattern_match"],
            "attack_candidates": [],
            "requires_llm": True,
        }

    # Best attack type = highest score
    best_candidate = max(candidates, key=lambda x: x["score"])
    best_type = best_candidate["type"]

    # OWASP CRS Decision Logic
    if inbound_anomaly_score >= INBOUND_ANOMALY_THRESHOLD:
        decision = "BLOCK"
        if inbound_anomaly_score >= 15:
            severity = "Critical"
        elif inbound_anomaly_score >= 10:
            severity = "High"
        else:
            severity = "High"
    else:
        if inbound_anomaly_score >= 3:
            decision = "REVIEW"
            severity = "Medium"
        else:
            decision = "MONITOR"
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
