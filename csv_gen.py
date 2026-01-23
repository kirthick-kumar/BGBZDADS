import pandas as pd

cols = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    *range(35), "label", "difficulty"
]

df = pd.read_csv(
    "KDDTest+.txt",
    header=None
)

df.columns = cols

test_df = pd.DataFrame({
    "host": "host_1",
    "service_node": df["service"]
})

test_df.head(20).to_csv("test_from_kdd.csv", index=False)
