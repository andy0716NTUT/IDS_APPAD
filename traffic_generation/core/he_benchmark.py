import time
import pandas as pd


def run_he_benchmark(
    df,
    pipeline,
    sensitive_cols,
    threshold=0.5
):

    latencies = []
    correct = 0

    for _, row in df.iterrows():

        record = row.to_dict()
        label = record["anomaly"]

        start = time.perf_counter()

        prob = pipeline.run(record, sensitive_cols)

        end = time.perf_counter()

        pred = int(prob > threshold)

        if pred == label:
            correct += 1

        latencies.append((end - start) * 1000)

    accuracy = correct / len(df)

    return {
        "accuracy": accuracy,
        "latency_avg_ms": sum(latencies) / len(latencies),
        "latency_max_ms": max(latencies),
        "latency_min_ms": min(latencies),
    }