MAX_FILE_SIZE_MB = 5

REQUIRED_FIELDS = [
    "timestamp",
    "user"
]

def validate_file_size(file):
    file.seek(0, 2)
    size_mb = file.tell() / (1024 * 1024)
    file.seek(0)

    if size_mb > MAX_FILE_SIZE_MB:
        raise ValueError("File exceeds maximum allowed size (5MB).")

    return True


def validate_logs(data):

    # Allow wrapped format like {"logs": [...]}
    if isinstance(data, dict) and "logs" in data:
        data = data["logs"]

    if not isinstance(data, list):
        raise ValueError("Logs must be a list of JSON objects.")

    for entry in data:
        if not isinstance(entry, dict):
            raise ValueError("Each log entry must be a JSON object.")

        for field in REQUIRED_FIELDS:
            if field not in entry:
                raise ValueError(f"Missing required field: {field}")

    return True
