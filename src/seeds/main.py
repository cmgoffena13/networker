from pathlib import Path

import polars as pl
import structlog

logger = structlog.getLogger(__name__)


def expand_port_range(port_str: str) -> list[int]:
    """Expand port ranges like '2194-2196' into individual ports."""
    if "-" in port_str:
        try:
            start, end = port_str.split("-", 1)
            return list(range(int(start.strip()), int(end.strip()) + 1))
        except (ValueError, AttributeError):
            return []
    try:
        return [int(port_str.strip())]
    except (ValueError, AttributeError):
        return []


def transform_ports():
    script_dir = Path(__file__).parent
    input_file = script_dir / "input" / "service-names-port-numbers.csv"
    output_file = script_dir / "output" / "ports.csv"

    ports_lazy = pl.scan_csv(input_file, schema_overrides={"Port Number": pl.Utf8})

    expanded_rows = []

    for batch_df in ports_lazy.collect(engine="streaming").iter_slices(n_rows=1000):
        for row in batch_df.iter_rows(named=True):
            port_str = str(row["Port Number"])
            ports_list = expand_port_range(port_str)
            protocol = str(row["Transport Protocol"]).upper()
            if protocol not in ["TCP", "UDP"]:
                continue
            for port_num in ports_list:
                expanded_rows.append(
                    {
                        "service_name": row["Service Name"],
                        "port_number": port_num,
                        "protocol": protocol,
                        "description": row["Description"],
                    }
                )

    ports_df = pl.DataFrame(expanded_rows)
    ports_df = ports_df.unique(subset=["port_number", "protocol"])
    ports_df = ports_df.sort("port_number", "protocol")
    ports_df.write_csv(output_file)


if __name__ == "__main__":
    transform_ports()
