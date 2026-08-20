import pandas
import numpy
import sklearn
import river

print("Pandas:", pandas.__version__)
print("NumPy:", numpy.__version__)
print("Scikit-learn:", sklearn.__version__)
print("River:", river.__version__)

from river import forest

model = forest.ARFClassifier()

print("\nARF successfully loaded!")
print(model)