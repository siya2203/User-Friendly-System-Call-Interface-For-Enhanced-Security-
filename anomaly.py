from sklearn.ensemble import IsolationForest
import numpy as np

def detect_anomaly():
    data = np.array([[1], [2], [3], [100]])

    model = IsolationForest()
    model.fit(data)

    predictions = model.predict(data)

    return predictions

if __name__ == "__main__":
    print(detect_anomaly())
