import time
from detector import predict

print("🚀 Starting Brute Force Simulation")

for i in range(60):

    # Small packet count
    features = [80] * 78

    predict(
        features,
        "172.16.0.99",
        force_label="BruteForce"
    )

    time.sleep(0.03)

print("✅ Brute Force Completed")