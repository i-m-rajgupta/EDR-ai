
import json
import re


TIMESTAMP_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,.]\d+)?)\s*\|\s*(.*)$"
)


def parse_log_text(text):
    events = []

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()

        if not line:
            continue

        timestamp = None
        payload = line

        match = TIMESTAMP_PATTERN.match(line)

        if match:
            timestamp, payload = match.groups()

        try:
            event = json.loads(payload)

            if not isinstance(event, dict):
                event = {"message": str(event)}

            event.setdefault("timestamp", timestamp)
            event.setdefault("event_id", None)
            event.setdefault("event_type", event.get("type", "UNKNOWN"))
            event.setdefault("severity", "INFO")
            event.setdefault("message", payload)
            event["_line"] = line_number

            events.append(event)

        except json.JSONDecodeError:
            # Preserve plain-text log lines for analysis.
            events.append({
                "timestamp": timestamp,
                "event_id": None,
                "event_type": "TEXT_LOG",
                "severity": "INFO",
                "message": payload,
                "_line": line_number,
            })

    return events
