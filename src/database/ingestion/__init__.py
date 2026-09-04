"""Aegis Patch Benchmark Ingestion Package.

Provides atomic, idempotent ingestion pipeline for loading benchmark data fixtures into SQLite.
"""

from src.database.ingestion.benchmark_ingestion import (
    IngestionSummary,
    ingest_benchmark,
    run_benchmark_ingestion,
)

__all__ = [
    "IngestionSummary",
    "ingest_benchmark",
    "run_benchmark_ingestion",
]
