from sklearn.ensemble import IsolationForest
import numpy as np

def detect_anomaly(syscall_name):
    """
    Takes a single syscall name and determines if it is an anomaly 
    based on a pre-defined or dynamically trained set.
    """
    # Convert syscall name to a numerical value for the ML model
    data = np.array([[hash(syscall_name) % 1000]])

    # contamination=0.1 means we expect 10% of calls to be potential anomalies
    model = IsolationForest(contamination=0.1, random_state=42)
    
    # In a real-life scenario, you would 'fit' on normal data first.
    # Here we simulate a quick check.
    model.fit(np.array([[hash("read")%1000], [hash("write")%1000], [hash("openat")%1000]]))
    prediction = model.predict(data)

    return prediction[0] # Returns -1 for anomaly, 1 for normal
