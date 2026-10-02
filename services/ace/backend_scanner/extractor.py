import base64
import re
from dataclasses import dataclass, field


@dataclass
class BackendProfile:
    language: str = "unknown"
    port_bindings: list[int] = field(default_factory=list)
    env_vars_used: list[str] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)


# .env exclusion — enforced at extractor level. Never parsed.
ENV_FILENAME_PATTERN = re.compile(r"(^|[\\/])\.env(\.|$)", re.IGNORECASE)

# Config files that are not source code and must never be scanned.
NON_SOURCE_PATTERN = re.compile(
    r"(deadCode|node_modules[\\/]|__pycache__[\\/]|\.git[\\/]|\.min\.js|test|spec|__tests__)",
    re.IGNORECASE,
)


class BackendExtractor:
    """Static extraction of ports, env vars and routes from backend source files.

    Usage:
        profile = BackendExtractor().extract([{language, filename, content(base64)}, ...])
    """

    def extract(self, source_files: list[dict]) -> BackendProfile:
        profile = BackendProfile()

        for f in source_files:
            filename = f.get("filename", "")
            if not self._is_scanable(filename):
                continue

            try:
                source = base64.b64decode(f["content"]).decode("utf-8", errors="ignore")
            except Exception:
                continue

            lang = f.get("language", "unknown")
            if profile.language == "unknown":
                profile.language = lang

            profile.port_bindings.extend(self._extract_ports(source, lang))
            profile.env_vars_used.extend(self._extract_env_vars(source, lang))
            profile.routes.extend(self._extract_routes(source, lang))
            profile.frameworks.extend(self._detect_frameworks(source, lang))

        profile.language = profile.language or "unknown"
        profile.port_bindings = sorted(set(p for p in profile.port_bindings if p))
        profile.env_vars_used = sorted(set(profile.env_vars_used))
        profile.routes = sorted(set(profile.routes))
        profile.frameworks = sorted(set(profile.frameworks))
        return profile

    def _is_scanable(self, filename: str) -> bool:
        """Return True when the file is safe to scan for backend references."""
        return not ENV_FILENAME_PATTERN.search(filename) and not NON_SOURCE_PATTERN.search(filename)

    def _extract_ports(self, source: str, lang: str) -> list[int]:
        ports = []
        patterns = [
            r"\.listen\s*\(\s*(\d+)",                 # Node: app.listen(3000)
            r"uvicorn\s+.*?--port\s+(\d+)",            # Python: uvicorn main:app --port 8000
            r"app\.run\s*\(.*?port\s*=\s*(\d+)",      # Flask: app.run(port=5000)
            r"PORT\s*=\s*int\s*\(\s*['\"]?(\d+)",     # PORT = int("8000")
            r"process\.env\.\w+\s*\|\|\s*(\d+)",      # Node: process.env.PORT || 3000
            r"ListenAndServe\s*\(\s*[\"']:(\d+)",     # Go: ListenAndServe(":8080",)
            r"--port\s+(\d+)",                         # generic: --port 8080
        ]
        for pattern in patterns:
            for m in re.finditer(pattern, source):
                try:
                    ports.append(int(m.group(1)))
                except ValueError:
                    pass
        return ports

    def _extract_env_vars(self, source: str, lang: str) -> list[str]:
        vars_found = []
        patterns = [
            r"os\.environ\[['\"]([\w_]+)['\"]\]",            # Python os.environ["X"]
            r"os\.getenv\s*\(\s*['\"]([\w_]+)['\"]",        # Python os.getenv("X")
            r"process\.env\.([\w_]+)",                        # Node process.env.X
            r"os\.Getenv\s*\(\s*['\"]([\w_]+)['\"]",        # Go os.Getenv("X")
        ]
        for pattern in patterns:
            for m in re.finditer(pattern, source):
                vars_found.append(m.group(1))
        return vars_found

    def _extract_routes(self, source: str, lang: str) -> list[str]:
        routes = []
        patterns = [
            r"@(?:app|router)\.\w+\s*\(\s*['\"](/[^'\"]*)['\"]",  # FastAPI/Flask
            r"router\.(?:get|post|put|delete|patch)\s*\(\s*['\"](/[^'\"]*)['\"]",  # Express
            r"app\.(?:get|post|put|delete|patch)\s*\(\s*['\"](/[^'\"]*)['\"]",   # Express app.get
            r"http\.HandleFunc\s*\(\s*['\"](/[^'\"]*)['\"]",        # Go net/http
        ]
        for pattern in patterns:
            for m in re.finditer(pattern, source):
                routes.append(m.group(1))
        return routes

    def _detect_frameworks(self, source: str, lang: str) -> list[str]:
        detected = []
        checks = {
            "fastapi": r"from fastapi|import fastapi",
            "flask": r"from flask|import flask",
            "express": r"require\(['\"]express['\"]|from ['\"]express['\"]",
            "gin": r"github\.com/gin-gonic/gin",
            "fiber": r"github\.com/gofiber/fiber",
        }
        for fw, pattern in checks.items():
            if re.search(pattern, source, re.IGNORECASE):
                detected.append(fw)
        return detected