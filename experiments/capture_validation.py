VALID_NPM_STATUSES = frozenset({"Allow", "Warn", "Block", "Quarantine", "Fallback"})


def validate_npm_entry(entry):
    if (not isinstance(entry, dict)
            or not isinstance(entry.get("package"), str)
            or not entry["package"]
            or not isinstance(entry.get("resolved"), str)
            or not entry["resolved"]
            or not isinstance(entry.get("status"), str)
            or entry["status"] not in VALID_NPM_STATUSES):
        raise ValueError("invalid dependency entry")


def validate_npm_capture(doc):
    if not isinstance(doc, dict) or not isinstance(doc.get("dependencies"), list):
        raise ValueError("missing or invalid dependencies array")
    if doc.get("errors") != []:
        raise ValueError(f"snapshot errors: {doc.get('errors', 'missing errors field')}")
    for entry in doc["dependencies"]:
        validate_npm_entry(entry)
    return doc["dependencies"]
