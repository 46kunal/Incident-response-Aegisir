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

    # 🔎 Explainability Layer
    df["risk_indicators"] = df.apply(lambda row: {
        "failed_login": int(row["is_failed"]),
        "unusual_ip": int(row["is_unusual_ip"]),
        "privilege_escalation": int(row["is_privilege_escalation"]),
        "sensitive_access": int(row["is_sensitive_access"]),
        "data_volume_mb": float(row["data_volume_mb"]),
        "login_hour": int(row["hour"])
    }, axis=1)

    return df, model
