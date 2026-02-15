import json
import random
from datetime import datetime, timedelta

# --------------------------
# Helper Functions
# --------------------------

def random_timestamp(start_time, minutes_range=300):
    return start_time + timedelta(minutes=random.randint(0, minutes_range))

def generate_ip(normal=True):
    if normal:
        return f"192.168.1.{random.randint(2, 50)}"
    else:
        return f"203.45.{random.randint(10, 99)}.{random.randint(1, 254)}"

# --------------------------
# Log Containers
# --------------------------

auth_logs = []
endpoint_logs = []
network_logs = []

base_time = datetime.now()

# --------------------------
# 1️⃣ Generate Normal Logs
# --------------------------

for i in range(100):
    timestamp = random_timestamp(base_time)
    user = f"user_{random.randint(1,5)}"

    # Auth logs
    auth_logs.append({
        "timestamp": timestamp.isoformat(),
        "user": user,
        "event_type": "login_attempt",
        "status": "success",
        "ip": generate_ip(normal=True)
    })

    # Endpoint logs
    endpoint_logs.append({
        "timestamp": timestamp.isoformat(),
        "user": user,
        "event_type": "file_access",
        "asset": "server_A",
        "sensitive_access": False
    })

    # Network logs
    network_logs.append({
        "timestamp": timestamp.isoformat(),
        "user": user,
        "event_type": "data_transfer",
        "destination_ip": generate_ip(normal=True),
        "data_volume_mb": random.randint(1, 50)
    })

# --------------------------
# 2️⃣ Inject Attack Scenario
# --------------------------

attacker_user = "user_3"
attack_start = base_time + timedelta(minutes=400)

# Failed login attempts
for i in range(6):
    auth_logs.append({
        "timestamp": (attack_start + timedelta(minutes=i)).isoformat(),
        "user": attacker_user,
        "event_type": "login_attempt",
        "status": "failed",
        "ip": generate_ip(normal=False)
    })

# Successful unusual login
auth_logs.append({
    "timestamp": (attack_start + timedelta(minutes=7)).isoformat(),
    "user": attacker_user,
    "event_type": "login_attempt",
    "status": "success",
    "ip": generate_ip(normal=False)
})

# Privilege escalation
endpoint_logs.append({
    "timestamp": (attack_start + timedelta(minutes=10)).isoformat(),
    "user": attacker_user,
    "event_type": "privilege_escalation",
    "asset": "server_A",
    "sensitive_access": True
})

# Sensitive file access
endpoint_logs.append({
    "timestamp": (attack_start + timedelta(minutes=12)).isoformat(),
    "user": attacker_user,
    "event_type": "file_access",
    "asset": "server_A",
    "sensitive_access": True
})

# Large data transfer
network_logs.append({
    "timestamp": (attack_start + timedelta(minutes=15)).isoformat(),
    "user": attacker_user,
    "event_type": "data_transfer",
    "destination_ip": generate_ip(normal=False),
    "data_volume_mb": 850
})

# --------------------------
# 3️⃣ Save to JSON
# --------------------------

with open("auth_logs.json", "w") as f:
    json.dump(auth_logs, f, indent=4)

with open("endpoint_logs.json", "w") as f:
    json.dump(endpoint_logs, f, indent=4)

with open("network_logs.json", "w") as f:
    json.dump(network_logs, f, indent=4)

print("Logs generated successfully.")
