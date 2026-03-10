"""Create a session with a specific playbook and start the scan."""
import requests
import sys
import time

BASE = "http://localhost:8002"
playbook = sys.argv[1] if len(sys.argv) > 1 else "recon_to_sqli"

# Get playbook prompt
presets = requests.get(f"{BASE}/api/presets").json()
if playbook not in presets:
    print(f"Unknown playbook: {playbook}. Available: {list(presets.keys())}")
    sys.exit(1)

prompt = presets[playbook]["prompt"]
print(f"Using playbook: {presets[playbook]['label']}")
print(f"Prompt length: {len(prompt)} chars")

# Create session
resp = requests.post(f"{BASE}/api/sessions", json={
    "target_url": "http://localhost:3000",
    "scope_mode": "full",
    "system_prompt": prompt,
})
session = resp.json()
sid = session["id"]
print(f"Session created: {sid}")

# Start scan
resp = requests.post(f"{BASE}/api/sessions/{sid}/start")
print(f"Scan started: {resp.json()}")

# Monitor
print("Waiting for scan to complete...")
while True:
    time.sleep(10)
    status = requests.get(f"{BASE}/api/sessions/{sid}").json()
    steps = status.get("total_steps", 0)
    findings = status.get("total_findings", 0)
    st = status["status"]
    print(f"  Status: {st} | Steps: {steps} | Findings: {findings}")
    if st in ("completed", "failed", "error"):
        break

# Print results
print(f"\n=== SCAN COMPLETE ===")
print(f"Session: {sid}")
print(f"Status: {status['status']}")
print(f"Steps: {status.get('total_steps', 0)}")
print(f"Findings: {status.get('total_findings', 0)}")
print(f"Duration: {(status.get('total_duration_ms') or 0) / 1000:.1f}s")

# List steps
steps_data = requests.get(f"{BASE}/api/sessions/{sid}/steps").json()
print(f"\nStep sequence:")
for s in steps_data:
    print(f"  Step {s['step_number']}: {s['tool_called']} [{s['phase']}] - {s['tool_input'][:80]}")
