"""Create entirely synthetic, reproducible firewall log data for the demo."""
from pathlib import Path

import numpy as np
import pandas as pd


def generate(n: int = 1200, seed: int = 24) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    start = pd.Timestamp("2025-04-01")
    times = start + pd.to_timedelta(rng.integers(0, 10 * 24 * 60, n), unit="m")
    high_traffic = rng.random(n) < 0.06
    received = rng.lognormal(mean=3.5, sigma=1.2, size=n).astype(int)
    sent = rng.lognormal(mean=3.4, sigma=1.5, size=n).astype(int)
    received[high_traffic] *= 60
    sent[high_traffic] *= 85
    duration = rng.lognormal(mean=2.8, sigma=1, size=n).round(2)
    duration[high_traffic] *= 15
    port = rng.choice([22, 53, 80, 443, 8080, 8443, 3306, 5432], size=n)
    source = rng.integers(1, 31, size=n)
    frame = pd.DataFrame({
        "DATE_TIME": times.strftime("%Y-%m-%d %H:%M:%S"),
        # Reserved documentation IP range; does not represent a real organization.
        "SOURCE_IP": [f"192.0.2.{i}" for i in source],
        "RCVD_BYTE": received,
        "SENT_BYTE": sent,
        "DURATION": duration,
        "DESTINATION_PORT": port,
        "ACTION": rng.choice(["accept", "deny"], size=n, p=[0.88, 0.12]),
    })
    # Deliberately injected synthetic outlier scenario for a useful UI demo.
    # These events are fictional and not labelled real attacks.
    unusual = frame.index[:12]
    frame.loc[unusual, "SOURCE_IP"] = "192.0.2.250"
    frame.loc[unusual, "DATE_TIME"] = [
        (pd.Timestamp("2025-04-06 02:00:00") + pd.Timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M:%S")
        for i in range(12)
    ]
    frame.loc[unusual, "RCVD_BYTE"] = 600
    frame.loc[unusual, "SENT_BYTE"] = 12000
    frame.loc[unusual, "DURATION"] = 12000
    frame.loc[unusual, "DESTINATION_PORT"] = 65000
    frame.loc[unusual, "ACTION"] = "deny"
    return frame


if __name__ == "__main__":
    output = Path(__file__).resolve().parents[1] / "data" / "sample_firewall_logs.csv"
    generate().to_csv(output, index=False)
    print(f"Wrote synthetic sample to {output}")
