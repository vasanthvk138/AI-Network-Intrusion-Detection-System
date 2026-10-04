import pandas as pd
import os

data_path = "data"
files = [f for f in os.listdir(data_path) if f.endswith(".csv")]

dfs = []

for file in files:
    try:
        print(f"📂 Loading: {file}")
        df = pd.read_csv(os.path.join(data_path, file), low_memory=False)

        # Fix column names (remove spaces)
        df.columns = df.columns.str.strip()

        dfs.append(df)

    except Exception as e:
        print(f"❌ Skipped {file}: {e}")

# Combine all
final_df = pd.concat(dfs, ignore_index=True)

print("✅ Final shape:", final_df.shape)

# Save combined dataset
final_df.to_csv(os.path.join(data_path, "final_dataset.csv"), index=False)

print("✅ Combined dataset created successfully")