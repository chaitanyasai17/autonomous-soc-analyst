"""
MITRE ATT&CK Enterprise Matrix reference data catalog.
Provides predefined tactics and techniques matching enterprise adversary behaviors
and Sigma detection rules.
"""

from typing import Any, Dict, List

TACTICS_CATALOG: List[Dict[str, str]] = [
    {"id": "TA0043", "short_name": "reconnaissance", "name": "Reconnaissance", "description": "Gather information to plan future adversary operations."},
    {"id": "TA0042", "short_name": "resource_development", "name": "Resource Development", "description": "Establish resources to support operations."},
    {"id": "TA0001", "short_name": "initial_access", "name": "Initial Access", "description": "Techniques that use various entry vectors to gain an initial foothold."},
    {"id": "TA0002", "short_name": "execution", "name": "Execution", "description": "Techniques that result in adversary-controlled code running on a local or remote system."},
    {"id": "TA0003", "short_name": "persistence", "name": "Persistence", "description": "Techniques used to maintain their foothold on systems across restarts or credential changes."},
    {"id": "TA0004", "short_name": "privilege_escalation", "name": "Privilege Escalation", "description": "Techniques used to gain higher-level permissions on a system or network."},
    {"id": "TA0005", "short_name": "defense_evasion", "name": "Defense Evasion", "description": "Techniques used to avoid detection throughout their compromise."},
    {"id": "TA0006", "short_name": "credential_access", "name": "Credential Access", "description": "Techniques for stealing credentials like account names and passwords."},
    {"id": "TA0007", "short_name": "discovery", "name": "Discovery", "description": "Techniques used to observe the environment and gain post-compromise knowledge."},
    {"id": "TA0008", "short_name": "lateral_movement", "name": "Lateral Movement", "description": "Techniques used to extend access across systems on the network."},
    {"id": "TA0009", "short_name": "collection", "name": "Collection", "description": "Techniques used to gather information and sources of target data."},
    {"id": "TA0011", "short_name": "command_and_control", "name": "Command and Control", "description": "Techniques used to communicate with systems under adversary control."},
    {"id": "TA0010", "short_name": "exfiltration", "name": "Exfiltration", "description": "Techniques used to steal data from your network."},
    {"id": "TA0040", "short_name": "impact", "name": "Impact", "description": "Techniques used to disrupt availability or compromise integrity by manipulating processes."},
]

TECHNIQUES_CATALOG: List[Dict[str, Any]] = [
    {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "credential_access",
        "description": "Adversaries may use brute force techniques to attempt credential guessing or password spraying.",
        "reference_url": "https://attack.mitre.org/techniques/T1110/",
    },
    {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "execution",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        "reference_url": "https://attack.mitre.org/techniques/T1059/",
    },
    {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution and defense evasion.",
        "reference_url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    {
        "technique_id": "T1218",
        "technique_name": "System Binary Proxy Execution (LOLBins)",
        "tactic": "defense_evasion",
        "description": "Adversaries may bypass process and signature-based defenses by proxying execution of malicious code through signed binaries.",
        "reference_url": "https://attack.mitre.org/techniques/T1218/",
    },
    {
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic": "credential_access",
        "description": "Adversaries may attempt to dump credentials from memory, SAM database, or NTDS.dit to obtain login secrets.",
        "reference_url": "https://attack.mitre.org/techniques/T1003/",
    },
    {
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
        "tactic": "persistence",
        "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring code execution.",
        "reference_url": "https://attack.mitre.org/techniques/T1053/",
    },
    {
        "technique_id": "T1547",
        "technique_name": "Boot or Logon Autostart Execution",
        "tactic": "persistence",
        "description": "Adversaries may configure system settings to automatically execute a program during system boot or logon.",
        "reference_url": "https://attack.mitre.org/techniques/T1547/",
    },
    {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts to determine vulnerabilities.",
        "reference_url": "https://attack.mitre.org/techniques/T1046/",
    },
    {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "privilege_escalation",
        "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as elevate privileges.",
        "reference_url": "https://attack.mitre.org/techniques/T1055/",
    },
    {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "initial_access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access or Persistence.",
        "reference_url": "https://attack.mitre.org/techniques/T1078/",
    },
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "initial_access",
        "description": "Adversaries may attempt to exploit vulnerabilities in Internet-facing programs like web servers or SQL engines.",
        "reference_url": "https://attack.mitre.org/techniques/T1190/",
    },
    {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "command_and_control",
        "description": "Adversaries may communicate using application layer protocols (HTTP/S, DNS) to avoid network detection.",
        "reference_url": "https://attack.mitre.org/techniques/T1071/",
    },
    {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "description": "An adversary may attempt to get detailed information about the operating system and hardware.",
        "reference_url": "https://attack.mitre.org/techniques/T1082/",
    },
    {
        "technique_id": "T1087",
        "technique_name": "Account Discovery",
        "tactic": "discovery",
        "description": "Adversaries may attempt to get a listing of valid local system or domain accounts.",
        "reference_url": "https://attack.mitre.org/techniques/T1087/",
    },
    {
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "tactic": "defense_evasion",
        "description": "Adversaries may attempt to make an executable or script difficult to discover or analyze.",
        "reference_url": "https://attack.mitre.org/techniques/T1027/",
    },
    {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "impact",
        "description": "Adversaries may target systems to cause a denial of service on local or remote applications.",
        "reference_url": "https://attack.mitre.org/techniques/T1499/",
    },
]
