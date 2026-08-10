import httpx
import time
import logging

logging.basicConfig(level=logging.INFO)

# Using the real Wazuh alert provided by the user
mock_alert = {
    "input": {
        "type": "log"
    },
    "agent": {
        "ip": "192.168.1.100",
        "name": "window_server",
        "id": "001"
    },
    "manager": {
        "name": "ubuntuserver"
    },
    "data": {
        "win": {
            "eventdata": {
                "image": "C:\\\\Windows\\\\system32\\\\cleanmgr.exe",
                "processGuid": "{e8e2694f-7464-6a74-6b01-000000001100}",
                "processId": "456",
                "utcTime": "2026-08-06 11:47:54.106",
                "targetFilename": "C:\\\\Users\\\\ADMINI~1\\\\AppData\\\\Local\\\\Temp\\\\4F497CBF-6916-4EE5-B708-3858DC3128BE\\\\WimProvider.dll",
                "ruleName": "DLL",
                "creationUtcTime": "2026-08-06 11:47:54.106",
                "user": "WIN-5RJ7UQ2G3GE\\\\Administrator"
            },
            "system": {
                "eventID": "11",
                "keywords": "0x8000000000000000",
                "providerGuid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
                "level": "4",
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "opcode": "0",
                "message": '"File created:\r\nRuleName: DLL\r\nUtcTime: 2026-08-06 11:47:54.106\r\nProcessGuid: {e8e2694f-7464-6a74-6b01-000000001100}\r\nProcessId: 456\r\nImage: C:\\Windows\\system32\\cleanmgr.exe\r\nTargetFilename: C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\4F497CBF-6916-4EE5-B708-3858DC3128BE\\WimProvider.dll\r\nCreationUtcTime: 2026-08-06 11:47:54.106\r\nUser: WIN-5RJ7UQ2G3GE\\Administrator"',
                "version": "2",
                "systemTime": "2026-08-06T11:47:54.109539900Z",
                "eventRecordID": "5844",
                "threadID": "3840",
                "computer": "WIN-5RJ7UQ2G3GE",
                "task": "11",
                "processID": "2388",
                "severityValue": "INFORMATION",
                "providerName": "Microsoft-Windows-Sysmon"
            }
        }
    },
    "rule": {
        "firedtimes": 28,
        "mail": True,
        "level": 15,
        "description": "Executable file dropped in folder commonly used by malware",
        "groups": [
            "sysmon",
            "sysmon_eid11_detections",
            "windows"
        ],
        "mitre": {
            "technique": [
                "Ingress Tool Transfer"
            ],
            "id": [
                "T1105"
            ],
            "tactic": [
                "Command and Control"
            ]
        },
        "id": "92213"
    },
    "location": "EventChannel",
    "decoder": {
        "name": "windows_eventchannel"
    },
    "id": "1786016877.147419314",
    "timestamp": "2026-08-06T11:47:57.311+0000"
}


print("\n--- Sending Mock Wazuh Alert to LIVE Webhook ---")
try:
    response = httpx.post("http://localhost:8000/webhook/wazuh", json=mock_alert, timeout=10.0)
    print(f"\nResponse Status: {response.status_code}")
    print(f"Response JSON: {response.json()}\n")
except Exception as e:
    print(f"\nFailed to connect to server. Ensure uvicorn is running on port 8000. Error: {e}")

print("--- Test Completed ---")
