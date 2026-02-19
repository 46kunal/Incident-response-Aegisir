import os
import json
import datetime

def write_audit_log(results):

    os.makedirs("logs", exist_ok=True)

    filename = f"logs/audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(filename, "w") as f:
        json.dump(results, f, indent=4)

    return filename
