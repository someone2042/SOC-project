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
        "name": "ubuntuserver",
        "id": "000"
    },
    "manager": {
        "name": "ubuntuserver"
    },
    "data": {
        "payload_printable": "...........j}.p:nq.....[.k_NkwQ...@.PgPh..>..*.,.+.0./.....$.#.(.'.\n...........=.<.5./.\n...W.........p3ar11fter.sbs..........\n.................\r.......................#...........",
        "tx_id": "0",
        "packet": "CAAn/yQGCAAnYL7hCABFAAAoACVAAIAGo9DAqAFkKFtsc8KrAbuOnHwgFLyi6FAQ+vDXQAAAAAAAAAAA",
        "app_proto": "tls",
        "packet_info": {
            "linktype": "1"
        },
        "in_iface": "em1",
        "src_ip": "192.168.1.100",
        "src_port": "49835",
        "event_type": "alert",
        "alert": {
            "severity": "1",
            "signature_id": "2057665",
            "rev": "2",
            "metadata": {
                "mitre_tactic_id": [
                    "TA0011"
                ],
                "performance_impact": [
                    "Low"
                ],
                "updated_at": [
                    "2024_11_28"
                ],
                "confidence": [
                    "High"
                ],
                "tls_state": [
                    "TLSEncrypt"
                ],
                "created_at": [
                    "2024_11_17"
                ],
                "mitre_technique_id": [
                    "T1071"
                ],
                "mitre_technique_name": [
                    "Application_Layer_Protocol"
                ],
                "mitre_tactic_name": [
                    "Command_And_Control"
                ],
                "signature_severity": [
                    "Critical"
                ],
                "deployment": [
                    "Perimeter"
                ],
                "malware_family": [
                    "Lumma_Stealer"
                ]
            },
            "gid": "1",
            "signature": "ET MALWARE Observed Win32/Lumma Stealer Related Domain (p3ar11fter .sbs in TLS SNI)",
            "action": "allowed",
            "source": {
                "port": "443",
                "ip": "40.91.108.115"
            },
            "category": "Domain Observed Used for C2 Detected",
            "target": {
                "port": "49835",
                "ip": "192.168.1.100"
            }
        },
        "payload": "FgMDAK4BAACqAwNqfZBwOm5xltCTxB9bFmtfTmt3Uf4LHkAfUGdQaPu9PgAAKsAswCvAMMAvAJ8AnsAkwCPAKMAnwArACcAUwBMAnQCcAD0APAA1AC8ACgEAAFcAAAATABEAAA5wM2FyMTFmdGVyLnNicwAFAAUBAAAAAAAKAAgABgAdABcAGAALAAIBAAANABQAEgQBBQECAQQDBQMCAwICBgEGAwAjAAAAFwAA/wEAAQA=",
        "stream": "1",
        "flow_id": "563773627319190.000000",
        "dest_ip": "40.91.108.115",
        "proto": "TCP",
        "tls": {
            "session_resumed": "true",
            "version": "TLS 1.2",
            "sni": "p3ar11fter.sbs"
        },
        "dest_port": "443",
        "pkt_src": "wire/pcap",
        "flow": {
            "src_ip": "192.168.1.100",
            "src_port": "49835",
            "pkts_toserver": "4",
            "dest_ip": "40.91.108.115",
            "start": "2026-08-13T09:37:54.590015+0000",
            "bytes_toclient": "3010",
            "bytes_toserver": "419",
            "pkts_toclient": "4",
            "dest_port": "443"
        },
        "timestamp": "2026-08-13T09:37:55.120764+0000",
        "direction": "to_server"
    },
    "rule": {
        "firedtimes": 13760,
        "mail": False,
        "level": 3,
        "description": "Suricata: Alert - ET MALWARE Observed Win32/Lumma Stealer Related Domain (p3ar11fter .sbs in TLS SNI)",
        "groups": [
            "ids",
            "suricata"
        ],
        "id": "86601"
    },
    "location": "192.168.1.1",
    "decoder": {
        "name": "json"
    },
    "id": "1786613876.118886776",
    "timestamp": "2026-08-13T09:37:56.266+0000"
}


print("\n--- Sending Mock Wazuh Alert to LIVE Webhook ---")
try:
    response = httpx.post("http://localhost:8000/webhook/wazuh", json=mock_alert, timeout=10.0)
    print(f"\nResponse Status: {response.status_code}")
    print(f"Response JSON: {response.json()}\n")
except Exception as e:
    print(f"\nFailed to connect to server. Ensure uvicorn is running on port 8000. Error: {e}")

print("--- Test Completed ---")
