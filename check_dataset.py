import pandas as pd

df = pd.read_csv("data/final_dataset.csv")

# 🔥 Fix column names (remove spaces)
df.columns = df.columns.str.strip()

print("\n📊 Columns:\n")
print(df.columns.tolist())

print("\n📊 Attack Distribution:\n")
print(df['Label'].value_counts())