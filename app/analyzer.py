
def analyze_events(events):
    findings = []

    for event in events:
        message = str(event.get("message", ""))
        event_type = str(event.get("event_type", "")).upper()
        severity = str(event.get("severity", "")).upper()

        indicators = []

        # Check for critical events
        if severity in {"CRITICAL", "FATAL"}:
            indicators.append("Critical severity event")

        # Check for YARA detections
        if "yara" in message.lower():
            indicators.append("YARA-related detection")

        # Check for suspicious PowerShell options
        message_lower = message.lower()

        if any(term in message_lower for term in [
            "-executionpolicy bypass",
            "-encodedcommand",
            "-enc "
        ]):
            indicators.append("Potentially suspicious PowerShell command")

        # Check for automatic process termination
        if "auto-killed" in message_lower or "auto_killed" in message_lower:
            indicators.append("Automatic process termination recorded")

        if indicators:
            findings.append({
                "line": event.get("_line"),
                "timestamp": event.get("timestamp"),
                "event_type": event_type,
                "severity": severity,
                "message": message,
                "indicators": "; ".join(indicators),
            })

    return findings
