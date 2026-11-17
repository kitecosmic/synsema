"""Regenerate v0.6.64 Parquet metadata fixtures with pyarrow 26.0.1.

Run from this directory: python v0664_generate.py
The tests compare the decoded statistics, not the binary file hash.
"""

from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq


HERE = Path(__file__).parent

pq.write_table(
    pa.table(
        {
            "k": [1, 3, None, 8, 5, 6],
            "v": [2.5, None, 4.0, 8.25, 9.5, None],
            "name": ["aa", "bb", None, "cc", "dd", "ee"],
        }
    ),
    HERE / "v0664_stats.parquet",
    row_group_size=3,
    write_statistics=True,
)

pq.write_table(
    pa.table(
        {
            "day": pa.array([date(2024, 1, 1), date(2024, 1, 3), date(2024, 2, 1), date(2024, 2, 2)]),
            "when": pa.array([datetime(2024, 1, 1, tzinfo=timezone.utc), datetime(2024, 1, 3, tzinfo=timezone.utc), datetime(2024, 2, 1, tzinfo=timezone.utc), datetime(2024, 2, 2, tzinfo=timezone.utc)]),
            "amount": pa.array([Decimal("1.20"), Decimal("3.40"), Decimal("5.60"), Decimal("7.80")], type=pa.decimal128(10, 2)),
            "u": pa.array([2**63, 2**63 + 1, 2**63 + 2, 2**63 + 3], type=pa.uint64()),
        }
    ),
    HERE / "v0664_logical_stats.parquet",
    row_group_size=2,
    write_statistics=True,
)

pq.write_table(
    pa.table({"a.b": [1, 2], "a": pa.array([{"b": 3}, {"b": 4}])}),
    HERE / "v0664_paths.parquet",
)
