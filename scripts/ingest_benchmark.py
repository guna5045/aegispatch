"""Developer CLI script to execute benchmark data ingestion into SQLite.

Usage:
    python scripts/ingest_benchmark.py
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.database import run_benchmark_ingestion

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aegis_patch.scripts.ingest_benchmark")


def main() -> int:
    """Execute benchmark ingestion into configured SQLite runtime database."""
    print("=" * 60)
    print("Aegis Patch — Benchmark Data Ingestion Pipeline")
    print("=" * 60)

    try:
        summary = run_benchmark_ingestion()
        print("\nIngestion Completed Successfully:")
        print(f"  • Assets:      {summary.total_assets} (Created: {summary.assets_created}, Updated: {summary.assets_updated})")
        print(f"  • Controls:    {summary.total_controls} (Created: {summary.controls_created}, Updated: {summary.controls_updated})")
        print(f"  • Findings:    {summary.total_findings} (Created: {summary.findings_created}, Updated: {summary.findings_updated})")
        print(f"  • Policies:    {summary.total_policies} (Created: {summary.policies_created}, Updated: {summary.policies_updated})")
        print(f"  • Threat Obs:  {summary.threat_observations_created} (Preserved offline baseline)")
        print(f"  • Processed:   {summary.total_processed} total records")
        print("=" * 60)
        return 0
    except Exception as exc:
        logger.error(f"Benchmark ingestion failed: {exc}", exc_info=True)
        print(f"\n[ERROR] Ingestion failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
