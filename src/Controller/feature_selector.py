class DynamicFeatureSelector:
    def __init__(self):
        self.selected = ["count", "bytes_norm"]

    def select(self, features):
        return {k: features[k] for k in self.selected if k in features}
