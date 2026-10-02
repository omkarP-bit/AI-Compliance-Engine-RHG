import base64

from ace.backend_scanner.extractor import BackendExtractor, ENV_FILENAME_PATTERN


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


FASTAPI_SOURCE = b64(
    """
import os
from fastapi import FastAPI
app = FastAPI()

DATABASE_URL = os.environ["DATABASE_URL"]
REDIS_URL    = os.getenv("REDIS_URL", "redis://localhost")

@app.get("/health")
async def health(): return {"status": "ok"}

@app.post("/ace/scan")
async def scan(): ...

# uvicorn main:app --port 8000
"""
)

NODE_SOURCE = b64(
    """
const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;
app.get('/health', (req, res) => res.json({ ok: true }));
app.listen(PORT);
"""
)

GO_SOURCE = b64(
    """
package main

import (
    "fmt"
    "net/http"
    "os"
)

func main() {
    db := os.Getenv("DATABASE_URL")
    http.HandleFunc("/health", handler)
    http.ListenAndServe(":8080", nil)
}
"""
)


class TestBackendExtractor:
    def setup_method(self):
        self.extractor = BackendExtractor()

    def test_empty_sources_returns_unknown_language(self):
        profile = self.extractor.extract([])
        assert profile.language == "unknown"
        assert profile.port_bindings == []
        assert profile.env_vars_used == []

    def test_extracts_python_ports(self):
        profile = self.extractor.extract(
            [{"language": "python", "filename": "main.py", "content": FASTAPI_SOURCE}]
        )
        assert 8000 in profile.port_bindings

    def test_extracts_python_env_vars(self):
        profile = self.extractor.extract(
            [{"language": "python", "filename": "main.py", "content": FASTAPI_SOURCE}]
        )
        assert "DATABASE_URL" in profile.env_vars_used
        assert "REDIS_URL" in profile.env_vars_used

    def test_extracts_python_routes(self):
        profile = self.extractor.extract(
            [{"language": "python", "filename": "main.py", "content": FASTAPI_SOURCE}]
        )
        assert "/health" in profile.routes
        assert "/ace/scan" in profile.routes

    def test_detects_fastapi_framework(self):
        profile = self.extractor.extract(
            [{"language": "python", "filename": "main.py", "content": FASTAPI_SOURCE}]
        )
        assert "fastapi" in profile.frameworks

    def test_extracts_node_port(self):
        profile = self.extractor.extract(
            [{"language": "node", "filename": "index.js", "content": NODE_SOURCE}]
        )
        assert 3000 in profile.port_bindings

    def test_extracts_node_env_vars(self):
        profile = self.extractor.extract(
            [{"language": "node", "filename": "index.js", "content": NODE_SOURCE}]
        )
        assert "PORT" in profile.env_vars_used

    def test_extracts_node_routes(self):
        profile = self.extractor.extract(
            [{"language": "node", "filename": "index.js", "content": NODE_SOURCE}]
        )
        assert "/health" in profile.routes

    def test_detects_express_framework(self):
        profile = self.extractor.extract(
            [{"language": "node", "filename": "index.js", "content": NODE_SOURCE}]
        )
        assert "express" in profile.frameworks

    def test_extracts_go_port(self):
        profile = self.extractor.extract(
            [{"language": "go", "filename": "main.go", "content": GO_SOURCE}]
        )
        assert 8080 in profile.port_bindings

    def test_extracts_go_env_vars(self):
        profile = self.extractor.extract(
            [{"language": "go", "filename": "main.go", "content": GO_SOURCE}]
        )
        assert "DATABASE_URL" in profile.env_vars_used

    def test_extracts_go_routes(self):
        profile = self.extractor.extract(
            [{"language": "go", "filename": "main.go", "content": GO_SOURCE}]
        )
        assert "/health" in profile.routes

    def test_env_file_is_always_excluded(self):
        env_content = b64("DATABASE_URL=postgres://secret\nAWS_SECRET=abc123")
        profile = self.extractor.extract(
            [
                {"language": "python", "filename": ".env", "content": env_content},
                {"language": "python", "filename": ".env.local", "content": env_content},
                {"language": "python", "filename": ".env.production", "content": env_content},
                {"language": "python", "filename": "config/.env", "content": env_content},
            ]
        )
        assert "DATABASE_URL" not in profile.env_vars_used
        assert "AWS_SECRET" not in profile.env_vars_used

    def test_env_filename_pattern_matches_all_variants(self):
        cases_match = [
            ".env",
            ".env.local",
            ".env.production",
            "config/.env",
            "services/ace/.env.test",
        ]
        cases_no_match = ["env_config.py", "environment.yaml", "dotenv.py", "main.py"]
        for fname in cases_match:
            assert ENV_FILENAME_PATTERN.search(fname), f"Should match: {fname}"
        for fname in cases_no_match:
            assert not ENV_FILENAME_PATTERN.search(fname), f"Should not match: {fname}"

    def test_node_modules_are_excluded(self):
        source = b64("const PORT = process.env.PORT || 3000;")
        profile = self.extractor.extract(
            [{"language": "node", "filename": "node_modules/x/index.js", "content": source}]
        )
        assert profile.env_vars_used == []
        assert profile.port_bindings == []

    def test_deduplicates_results(self):
        profile = self.extractor.extract(
            [
                {"language": "python", "filename": "a.py", "content": FASTAPI_SOURCE},
                {"language": "python", "filename": "b.py", "content": FASTAPI_SOURCE},
            ]
        )
        assert profile.env_vars_used.count("DATABASE_URL") == 1
        assert profile.routes.count("/health") == 1