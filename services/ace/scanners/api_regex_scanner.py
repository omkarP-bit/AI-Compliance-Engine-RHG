import re
from typing import Any, Dict, List


class APIFindingsScanner:
    """Regex-based API security scanner with line numbers and snippets."""

    def __init__(self, min_severity: str = None):
        self.min_severity = (min_severity or "INFO").upper()
        self._order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    def scan(self, content: str, filename: str, language: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        min_s = self._order.get(self.min_severity, 0)

        patterns = [
            # Secrets
            (r"(?:AWS_SECRET_ACCESS_KEY|AWS_SECRET|SECRET_KEY|PRIVATE_KEY)\s*=\s*['\"][^'\"]{8,}['\"]", "API-SEC-001", "Hardcoded secret detected", "HIGH", "Avoid hardcoding secrets. Use environment variables or secret managers."),
            (r"(?:password|passwd|pwd|pass)\s*=\s*['\"][^'\"]{4,}['\"]", "API-SEC-002", "Hardcoded password detected", "HIGH", "Remove hardcoded credentials. Use secure secret management."),
            (r"(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*=\s*['\"][A-Za-z0-9_\-+/=]{16,}['\"]", "API-SEC-003", "Hardcoded API key/token detected", "HIGH", "Move to secure credential storage (env vars/secret manager)."),
            (r"bearer\s+[A-Za-z0-9_\-\.]{20,}", "API-SEC-004", "Hardcoded Bearer token detected", "HIGH", "Never hardcode tokens. Use secure credential storage."),
            # SQL Injection
            (r"(?:execute|query|raw|sql)\s*\(\s*['\"][^'\"]*(?:%s|\+|concat|\$\{|f['\"])", "API-SEC-010", "Potential SQL string concatenation/interpolation", "HIGH", "Use parameterized queries/prepared statements (OWASP A03:2021)."),
            (r"(?:cursor\.execute|db\.query|connection\.query)\s*\([^,)]*\+", "API-SEC-011", "SQL query built via string concatenation", "HIGH", "Use bound parameters to prevent SQL injection."),
            (r"WHERE.*\+.*['\"]", "API-SEC-012", "Dynamic SQL construction detected", "HIGH", "Use parameterized queries with proper placeholders."),
            # NoSQL Injection
            (r"\$where\s*:", "API-SEC-013", "MongoDB $where operator usage", "HIGH", "Avoid $where; use query operators or parameterized queries."),
            (r"find\s*\(\s*\{[^}]*\$\{", "API-SEC-014", "NoSQL query with string interpolation", "HIGH", "Use parameterized NoSQL queries to prevent injection."),
            # Command Injection
            (r"\beval\s*\(", "API-SEC-020", "Use of eval() is dangerous", "HIGH", "Avoid eval(). Use safe alternatives (OWASP A03)."),
            (r"\bexec\s*\(", "API-SEC-021", "Use of exec() is dangerous", "HIGH", "Avoid exec() with untrusted input."),
            (r"subprocess\.(?:call|Popen|run|check_output).*shell\s*=\s*True", "API-SEC-022", "subprocess with shell=True enables command injection", "CRITICAL", "Avoid shell=True or strictly sanitize inputs. Use args list."),
            (r"os\.system\s*\(", "API-SEC-023", "os.system() usage - command injection risk", "HIGH", "Use subprocess with shell=False and args list."),
            (r"child_process\.(?:exec|execSync)\s*\(", "API-SEC-024", "Node child_process.exec with potential shell injection", "HIGH", "Use spawn/execFile with args array, not shell string concatenation."),
            (r"spawn\s*\([^,]+,\s*[^[]", "API-SEC-025", "Potential unsafe command execution", "MEDIUM", "Use array of args, avoid string concatenation."),
            # Weak crypto
            (r"hashlib\.(?:md5|sha1)\s*\(", "API-SEC-030", "Weak hash algorithm (MD5/SHA1)", "MEDIUM", "Use SHA-256 or stronger for security purposes (OWASP A02)."),
            (r"crypto\.createHash\s*\(\s*['\"](?:md5|sha1)['\"]", "API-SEC-031", "Weak hash algorithm in Node", "MEDIUM", "Use SHA-256 or better."),
            (r"MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-1)['\"]", "API-SEC-032", "Weak hash in Java", "MEDIUM", "Use SHA-256 or stronger."),
            (r"CryptoJS\.(?:MD5|SHA1)", "API-SEC-033", "Weak hash in CryptoJS", "MEDIUM", "Use stronger hash algorithms."),
            # Debug/Dev settings
            (r"app\.run\s*\([^)]*debug\s*=\s*True", "API-SEC-040", "Debug mode enabled in production", "MEDIUM", "Disable debug in production (OWASP A05)."),
            (r"DEBUG\s*=\s*True", "API-SEC-041", "DEBUG=True in configuration", "MEDIUM", "Disable debug mode in production."),
            (r"app\.debug\s*=\s*True", "API-SEC-042", "Flask app.debug enabled", "MEDIUM", "Disable debug mode in production."),
            # CORS
            (r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]?\*", "API-SEC-050", "CORS allows all origins (*)", "MEDIUM", "Restrict CORS to specific trusted origins (OWASP A01)."),
            (r"cors\s*\([^)]*origin\s*:\s*['\"]\*['\"]", "API-SEC-051", "CORS wildcard origin", "MEDIUM", "Whitelist specific origins, not wildcard."),
            (r"app\.use\s*\(\s*cors\s*\(\s*\)\s*\)", "API-SEC-052", "CORS enabled with default (permissive) settings", "MEDIUM", "Configure CORS with specific allowed origins."),
            # Auth/JWT issues
            (r"jwt\.decode\s*\([^)]*verify\s*=\s*False", "API-SEC-060", "JWT verification disabled", "CRITICAL", "Always verify JWT signatures (OWASP A07)."),
            (r"algorithms\s*=\s*\[['\"]none['\"]\]", "API-SEC-061", "JWT 'none' algorithm allowed", "CRITICAL", "Reject 'none' algorithm in JWT validation."),
            (r"jwt\.sign\s*\([^)]*algorithm\s*:\s*['\"]none['\"]", "API-SEC-062", "JWT signed with 'none' algorithm", "CRITICAL", "Use strong signing algorithms (RS256/HS256)."),
            (r"verify\s*:\s*false.*jwt|jwt.*verify\s*:\s*false", "API-SEC-063", "JWT verification bypassed", "CRITICAL", "Never disable JWT verification."),
            # Path traversal/File access
            (r"open\s*\([^)]*(?:request\.|req\.|params|input|body)", "API-SEC-070", "File open with potentially user-controlled path", "HIGH", "Validate and sanitize file paths, use allowlists (OWASP A01)."),
            (r"fs\.readFile\s*\([^)]*(?:req\.|request\.|params|query|body)", "API-SEC-071", "Untrusted input in file read (potential path traversal)", "HIGH", "Validate paths against allowlist, prevent directory traversal."),
            (r"fs\.writeFile\s*\([^)]*(?:req\.|request\.|params)", "API-SEC-072", "Untrusted input in file write", "HIGH", "Validate paths and prevent arbitrary file writes."),
            (r"sendFile\s*\([^)]*(?:req\.|request\.|params)", "API-SEC-073", "Potential path traversal in sendFile", "HIGH", "Use resolved paths and validate against allowlist."),
            (r"\.\.\/|\.\.\\", "API-SEC-074", "Directory traversal pattern detected", "MEDIUM", "Validate and normalize file paths, reject traversal attempts."),
            # Insecure HTTP
            (r"['\"]http://(?!localhost|127\.0\.0\.1)[^'\"]+['\"]", "API-SEC-080", "Insecure HTTP URL to external host", "LOW", "Use HTTPS for external communications (OWASP A02)."),
            (r"['\"]http://localhost[^'\"]*['\"]", "API-SEC-081", "HTTP to localhost (dev only - review)", "INFO", "Ensure not used in production."),
            # XSS
            (r"innerHTML\s*=", "API-SEC-090", "Use of innerHTML with potential XSS", "MEDIUM", "Use textContent or sanitize HTML (OWASP A03)."),
            (r"dangerouslySetInnerHTML", "API-SEC-091", "React dangerouslySetInnerHTML usage", "MEDIUM", "Sanitize HTML with DOMPurify or avoid."),
            (r"document\.write\s*\(", "API-SEC-092", "document.write() XSS risk", "MEDIUM", "Avoid document.write(), use DOM manipulation safely."),
            (r"\.html\s*\([^)]*(?:req\.|request\.)", "API-SEC-093", "Unescaped user input in HTML response", "MEDIUM", "Sanitize and encode all user input."),
            # SSRF
            (r"(?:fetch|axios\.get|requests\.get|http\.get)\s*\([^)]*(?:req\.|request\.|params)", "API-SEC-100", "Potential SSRF with user-controlled URL", "HIGH", "Validate and allowlist outbound requests (OWASP A10)."),
            (r"urllib\.request\.urlopen\s*\([^)]*(?:req\.|request\.)", "API-SEC-101", "SSRF risk with urlopen", "HIGH", "Validate URLs against allowlist."),
            # Insecure deserialization
            (r"pickle\.loads\s*\(", "API-SEC-110", "Insecure deserialization with pickle", "CRITICAL", "Avoid pickle with untrusted data. Use safe formats like JSON."),
            (r"yaml\.load\s*\((?![^)]*Loader)", "API-SEC-111", "Unsafe YAML deserialization", "HIGH", "Use yaml.safe_load() instead of yaml.load()."),
            (r"unserialize\s*\(", "API-SEC-112", "PHP unserialize() deserialization risk", "HIGH", "Avoid unserialize with untrusted data."),
            # Weak crypto ciphers
            (r"crypto\.createDecipher|createCipher", "API-SEC-120", "Weak/deprecated crypto API usage", "HIGH", "Use createCipheriv/createDecipheriv with secure modes (OWASP A02)."),
            (r"\bDES(?:ede)?\b\bRC4\b|\bBlowfish\b|\b3DES\b", "API-SEC-121", "Weak/obsolete cryptographic algorithm", "HIGH", "Use AES-GCM or ChaCha20-Poly1305 (OWASP A02)."),
            (r"Math\.random\s*\(\)", "API-SEC-122", "Insecure random for security purposes", "MEDIUM", "Use crypto.randomBytes() for security-critical randomness."),
            # Mass assignment / excessive data exposure hints
            (r"Object\.assign\s*\([^,]+,\s*req\.body", "API-SEC-130", "Mass assignment risk with req.body", "MEDIUM", "Whitelist allowed fields explicitly (OWASP API3)."),
            (r"\.update\s*\(\s*req\.body", "API-SEC-131", "Mass assignment in update operation", "MEDIUM", "Use DTOs/whitelists to prevent over-posting."),
            # Security misconfig
            (r"helmet\s*\(\s*\)\s*", "API-SEC-140", "Review helmet configuration", "INFO", "Ensure security headers properly configured."),
            (r"X-Powered-By", "API-SEC-141", "X-Powered-By header exposure", "LOW", "Remove server/framework identification headers."),
        ]

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') and not any(k in stripped.lower() for k in ['password', 'secret', 'key', 'token', 'api']):
                continue
            if stripped.startswith('//') and not any(k in stripped.lower() for k in ['password', 'secret', 'key', 'token']):
                continue
            for pattern, rule_id, title, severity, rec in patterns:
                if self._order.get(severity, 0) < min_s:
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "rule_id": rule_id,
                        "title": title,
                        "description": title,
                        "severity": severity,
                        "artifact": filename,
                        "file": filename,
                        "line_number": i,
                        "line": i,
                        "snippet": stripped[:200],
                        "code_snippet": stripped[:200],
                        "recommendation": rec,
                        "source": "api-regex",
                    })
                    break

        return findings
