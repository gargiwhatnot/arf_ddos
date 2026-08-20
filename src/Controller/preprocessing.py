class Preprocessor:
    def normalize(self, features):
        return {
            "count": features["count"],
            "bytes_norm": features["bytes"] / 1500.0
        }
