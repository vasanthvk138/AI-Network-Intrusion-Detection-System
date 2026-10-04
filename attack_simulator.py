import time
from src.detector import predict

print("🚀 Starting Port Scan Simulation")

for i in range(50):

    # High packet count
    features = [500] * 78

    predict(
        features,
        "192.168.0.13"
    )

    time.sleep(0.05)

print("✅ Port Scan Completed")