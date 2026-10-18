"""Train an Isolation Forest pipeline from a CSV file."""
import argparse
from pathlib import Path

import joblib
import pandas as pd
from risk_pipeline import preprocess_data, train_model


def main() -> None:
    parser = argparse.ArgumentParser(description="Train a firewall anomaly model")
    parser.add_argument("--data", required=True, type=Path, help="Input training CSV")
    parser.add_argument("--model", type=Path, default=Path("artifacts/model.joblib"))
    parser.add_argument("--contamination", type=float, default=0.05)
    args = parser.parse_args()

    data = pd.read_csv(args.data, low_memory=False)
    model = train_model(preprocess_data(data), contamination=args.contamination)
    args.model.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.model)
    print(f"Trained on {len(data):,} rows; saved model to {args.model}")
    print("Scores are heuristic; no attack-detection accuracy is implied.")


if __name__ == "__main__":
    main()
