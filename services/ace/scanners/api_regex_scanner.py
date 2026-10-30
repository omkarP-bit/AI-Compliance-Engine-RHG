import re
from typing import Any, Dict, List


class APIFindingsScanner:
    """Regex-based API security scanner with line numbers and snippets."""

    def scan(self, content: str, filename: str, language: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()

        patterns = [
            # Secrets
            (r"(?:AWS_SECRET_ACCESS_KEY|AWS_SECRET|SECRET_KEY)\s*=\s*['\"][^'\"]{8,}['\"]", "API-SEC-001", "Hardcoded secret detected", "HIGH", "Avoid hardcoding secrets. Use environment variables or secret managers."),
            (r"(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]", "API-SEC-002", "Hardcoded password detected", "HIGH", "Remove hardcoded credentials."),
            (r"(?:api[_-]?key|token)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "API-SEC-003", "Hardcoded API key/token detected", "HIGH", "Move to secure credential storage."),
            # SQL Injection
            (r"(?:execute|query)\s*\(\s*['\"][^'\"]*(?:%s|\+|\$\{|f['\"])", "API-SEC-010", "Potential SQL string concatenation/interpolation", "HIGH", "Use parameterized queries/prepared statements."),
            (r"cursor\.execute\s*\([^)]*\+", "API-SEC-011", "SQL query built via string concatenation", "HIGH", "Use bound parameters."),
            # Dangerous functions
            (r"\beval\s*\(", "API-SEC-020", "Use of eval() is dangerous", "HIGH", "Avoid eval(). Use safe alternatives."),
            (r"\bexec\s*\(", "API-SEC-021", "Use of exec() is dangerous", "HIGH", "Avoid exec() with untrusted input."),
            (r"subprocess\.(?:call|Popen|run).*shell\s*=\s*True", "API-SEC-022", "subprocess with shell=True", "HIGH", "Avoid shell=True or sanitize inputs strictly."),
            (r"child_process\.(?:exec|execSync)\s*\(", "API-SEC-023", "Node child_process.exec with potential shell injection", "HIGH", "Use spawn with args array."),
            # Weak crypto
            (r"hashlib\.(?:md5|sha1)\s*\(", "API-SEC-030", "Weak hash algorithm (MD5/SHA1)", "MEDIUM", "Use SHA-256 or stronger for security purposes."),
            (r"crypto\.createHash\s*\(\s*['\"](?:md5|sha1)['\"]", "API-SEC-031", "Weak hash algorithm in Node", "MEDIUM", "Use SHA-256 or better."),
            # Debug
            (r"app\.run\s*\([^)]*debug\s*=\s*True", "API-SEC-040", "Debug mode enabled", "MEDIUM", "Disable debug in production."),
            (r"DEBUG\s*=\s*True", "API-SEC-041", "DEBUG=True in configuration", "MEDIUM", "Disable debug mode in production."),
            # CORS
            (r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]?\*", "API-SEC-050", "CORS allows all origins (*)", "MEDIUM", "Restrict CORS to specific trusted origins."),
            (r"cors\s*\([^)]*origin\s*:\s*['\"]\*['\"]", "API-SEC-051", "CORS wildcard origin", "MEDIUM", "Whitelist specific origins."),
            # JWT issues
            (r"jwt\.decode\s*\([^)]*verify\s*=\s*False", "API-SEC-060", "JWT verification disabled", "HIGH", "Always verify JWT signatures."),
            (r"algorithms\s*=\s*\[['\"]none['\"]\]", "API-SEC-061", "JWT 'none' algorithm allowed", "HIGH", "Reject 'none' algorithm."),
            # Path traversal
            (r"open\s*\([^)]*(?:request\.|req\.|params|input)", "API-SEC-070", "File open with potentially user-controlled path", "HIGH", "Validate and sanitize file paths, use allowlists."),
            # Insecure HTTP
            (r"['\"]http://[^'\"]+['\"]", "API-SEC-080", "Insecure HTTP URL detected", "LOW", "Use HTTPS for external communications."),
        ]

        for i, line in enumerate(lines, 1):
            # Skip comments in general, but still check for hardcoded secrets
            stripped = line.strip()
            if stripped.startswith('#') and 'password' not in stripped.lower() and 'secret' not in stripped.lower() and 'key' not in stripped.lower():
                continue
            for pattern, rule_id, title, severity, rec in patterns:
                if re.search(pattern, line):
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
                    break  # one finding per line to avoid noise

        return findings
