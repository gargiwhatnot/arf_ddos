import pandas as pd
from pathlib import Path

file_path = Path("../dataset/01-12/DrDoS_DNS.csv")

df = pd.read_csv(file_path, nrows=1000)

print("Columns with their data types\n")

for column, dtype in zip(df.columns, df.dtypes):
    print(f"{column} ---> {dtype}")