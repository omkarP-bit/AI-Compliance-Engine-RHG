from __future__ import annotations

import os

from .base import StorageBackend

_cached: StorageBackend | None = None


def get_storage_backend() -> StorageBackend:
    global _cached
    if _cached is not None:
        return _cached

    backend = os.environ.get("STORAGE_BACKEND", "").strip().lower()

    if not backend:
        if os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or os.environ.get("AWS_EXECUTION_ENV"):
            backend = "dynamodb"
        else:
            backend = "postgres"

    if backend == "dynamodb":
        from .dynamodb import DynamoDBStorage

        _cached = DynamoDBStorage()
        return _cached

    if backend == "postgres":
        from .postgres import PostgresStorage

        _cached = PostgresStorage()
        return _cached

    from .postgres import PostgresStorage

    _cached = PostgresStorage()
    return _cached
