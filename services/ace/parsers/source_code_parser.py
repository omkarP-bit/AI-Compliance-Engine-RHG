import re

from .base import BaseParser, NormalizedArtifact


class SourceCodeParser(BaseParser):
    """Parser for API/application source code files."""

    def supports(self, name: str) -> bool:
        lower = name.lower()
        if lower.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php")):
            if "node_modules" in lower or "__pycache__" in lower:
                return False
            return True
        return False

    def parse(self, content: str, name: str) -> NormalizedArtifact:
        lower = name.lower()
        lang = "unknown"
        if lower.endswith(".py"):
            lang = "python"
        elif lower.endswith((".js", ".jsx")):
            lang = "node"
        elif lower.endswith((".ts", ".tsx")):
            lang = "typescript"
        elif lower.endswith(".go"):
            lang = "go"
        elif lower.endswith(".java"):
            lang = "java"
        elif lower.endswith(".rb"):
            lang = "ruby"
        elif lower.endswith(".php"):
            lang = "php"

        routes = []
        for m in re.finditer(r"@(?:app|router)\.(?:get|post|put|delete|patch|options)\s*\(\s*['\"]([^'\"]+)['\"]", content):
            routes.append(m.group(1))
        for m in re.finditer(r"(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]", content):
            routes.append(m.group(1))
        for m in re.finditer(r"@(?:route|RequestMapping)\s*\(\s*['\"]([^'\"]+)['\"]", content):
            routes.append(m.group(1))

        raw = {
            "kind": "SourceCode",
            "language": lang,
            "filename": name,
            "routes": sorted(set(routes)),
            "content": content,
            "imports": self._extract_imports(content, lang),
        }
        metadata = {
            "artifact_type": "source_code",
            "language": lang,
            "routes_count": len(routes),
        }
        return NormalizedArtifact(artifact_type="source_code", name=name, raw=raw, metadata=metadata)

    def _extract_imports(self, content: str, lang: str) -> list:
        imports = []
        if lang == "python":
            for m in re.finditer(r"^(?:from|import)\s+([^\s]+)", content, re.M):
                imports.append(m.group(1))
        elif lang in ("node", "typescript"):
            for m in re.finditer(r"require\s*\(\s*['\"]([^'\"]+)['\"]", content):
                imports.append(m.group(1))
            for m in re.finditer(r"from\s+['\"]([^'\"]+)['\"]", content):
                imports.append(m.group(1))
        return imports[:30]
