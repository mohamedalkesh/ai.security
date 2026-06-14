"""MITRE ATT&CK mapping for the supported attack classes."""

from __future__ import annotations

from typing import Dict


MITRE_MAPPING: Dict[str, Dict[str, str]] = {
    "Benign": {
        "technique": "N/A",
        "tactic": "N/A",
        "severity": "Informational",
        "description": "Normal network traffic with no malicious behavior detected.",
    },
    "Brute Force": {
        "technique": "T1110",
        "tactic": "Credential Access",
        "severity": "High",
        "description": "Adversary attempts repeated password/login guessing.",
    },
    "Port Scan": {
        "technique": "T1046",
        "tactic": "Discovery",
        "severity": "Medium",
        "description": "Adversary scans network services and open ports.",
    },
    "DDoS": {
        "technique": "T1498",
        "tactic": "Impact",
        "severity": "High",
        "description": "Adversary degrades service availability via traffic flooding.",
    },
    "ICMP Flood": {
        "technique": "T1498.001",
        "tactic": "Impact",
        "severity": "High",
        "description": "ICMP echo flood (ping flood / smurf) saturating the target with Layer-3 traffic.",
    },
    "ICMP Sweep": {
        "technique": "T1018",
        "tactic": "Discovery",
        "severity": "Medium",
        "description": "ICMP ping sweep probing many hosts to map live systems on the network.",
    },
    "DoS": {
        "technique": "T1499",
        "tactic": "Impact",
        "severity": "High",
        "description": "Application-layer denial of service exhausting target resources.",
    },
    "Bot": {
        "technique": "T1071",
        "tactic": "Command and Control",
        "severity": "High",
        "description": "Compromised host communicating with botnet C2 infrastructure.",
    },
    "Web Attack": {
        "technique": "T1190",
        "tactic": "Initial Access",
        "severity": "High",
        "description": "Exploitation attempt against a public-facing web application (XSS / SQLi / web brute force).",
    },
    "SQL Injection": {
        "technique": "T1190",
        "tactic": "Initial Access",
        "severity": "High",
        "description": "Malicious SQL payload attempts to manipulate database queries or extract sensitive records.",
    },
    "XSS": {
        "technique": "T1059.007",
        "tactic": "Execution",
        "severity": "Medium",
        "description": "Cross-site scripting payload attempts to execute attacker-controlled script in a user browser.",
    },
    "Command Injection": {
        "technique": "T1059",
        "tactic": "Execution",
        "severity": "Critical",
        "description": "Input payload attempts to execute operating system commands on the target application server.",
    },
    "Path Traversal": {
        "technique": "T1005",
        "tactic": "Collection",
        "severity": "High",
        "description": "Request attempts to access files outside the intended web root using traversal sequences.",
    },
    "Ransomware": {
        "technique": "T1486",
        "tactic": "Impact",
        "severity": "Critical",
        "description": "Behavior resembles encryption or destructive activity intended to deny access to data.",
    },
    "Malware": {
        "technique": "T1105",
        "tactic": "Command and Control",
        "severity": "Critical",
        "description": "Traffic pattern suggests malware download, beaconing, or suspicious payload delivery.",
    },
    "DNS Tunneling": {
        "technique": "T1071.004",
        "tactic": "Command and Control",
        "severity": "High",
        "description": "DNS traffic appears to carry encoded command-and-control or data exfiltration content.",
    },
    "ARP Spoofing": {
        "technique": "T1557.002",
        "tactic": "Credential Access",
        "severity": "High",
        "description": "Local network traffic suggests ARP poisoning or man-in-the-middle positioning.",
    },
    "Data Exfiltration": {
        "technique": "T1041",
        "tactic": "Exfiltration",
        "severity": "Critical",
        "description": "Large or unusual outbound transfer may indicate data being exfiltrated over the network.",
    },
    "Lateral Movement": {
        "technique": "T1021",
        "tactic": "Lateral Movement",
        "severity": "High",
        "description": "Internal connection pattern suggests movement between systems after initial compromise.",
    },
    "C2 Beaconing": {
        "technique": "T1071",
        "tactic": "Command and Control",
        "severity": "High",
        "description": "Periodic outbound communication resembles command-and-control beacon traffic.",
    },
    "Infiltration": {
        "technique": "T1133",
        "tactic": "Initial Access",
        "severity": "Critical",
        "description": "Adversary established a foothold and is performing lateral movement / internal recon.",
    },
    "Unknown": {
        "technique": "Unknown",
        "tactic": "Unknown",
        "severity": "Low",
        "description": "Model confidence below threshold, analyst review required.",
    },
}


def enrich(label: str) -> Dict[str, str]:
    """Return MITRE info for a given label, falling back to Unknown."""
    return MITRE_MAPPING.get(label, MITRE_MAPPING["Unknown"])
