import time
from detector import predict

print("🚀 Starting DDoS Simulation")

for i in range(80):

    # Medium packet count
    features = [200] * 78

    predict(
        features,
        "10.0.0.55",
        force_label="DDoS"
    )

    time.sleep(0.02)

print("✅ DDoS Completed")