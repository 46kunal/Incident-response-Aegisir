from sklearn.ensemble import IsolationForest

def train_anomaly_model(df):

    feature_columns = [
        "is_failed",
        "is_unusual_ip",
        "is_privilege_escalation",
        "is_sensitive_access",
        "data_volume_mb",
        "hour"
    ]

    X = df[feature_columns]

    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X)

    df["anomaly_score"] = model.decision_function(X)
    df["anomaly_flag"] = model.predict(X)

    return df, model
