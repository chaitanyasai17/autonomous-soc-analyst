"""
Prompt builder for AI Threat Analysis.
Structures contextual input from logs, Sigma detections, MITRE context, and risk data.
"""

from __future__ import annotations

from typing import Any, Dict

SYSTEM_PROMPT = """You are a Principal SOC Analyst and Threat Intelligence Hunter.
Your task is to analyze security events, Sigma detections, and MITRE ATT&CK telemetry.
Evaluate the severity, reconstruct the attack narrative, evaluate the likelihood of false positives,
and recommend concrete incident response triage and containment actions.

You MUST respond strictly in valid JSON matching this schema:
{
    "threat_summary": "Concise 2-sentence executive summary of the threat",
    "attack_narrative": "Detailed technical explanation of the adversary technique observed",
    "confidence": 0.85,
    "false_positive_likelihood": "low|medium|high",
    "false_positive_rationale": "Why this could or could not be a benign administrative activity",
    "recommended_actions": ["Action 1", "Action 2", "Action 3"],
    "indicators_of_compromise": [{"type": "ip|hash|domain|pattern", "value": "value", "description": "desc"}],
    "mitre_alignment": ["T1218", "T1059"]
}
"""


def build_analysis_prompt(context: Dict[str, Any]) -> str:
    """Constructs user prompt from context dictionary."""
    return f"""Analyze the following SOC security event detection:

DETECTION INFORMATION:
- Rule Title: {context.get('rule_title', 'Unknown')}
- Rule Category: {context.get('rule_category', 'General')}
- Detection Severity: {context.get('severity', 'Medium')}
- Confidence: {context.get('confidence', 1.0)}
- Detection Timestamp: {context.get('timestamp', 'N/A')}
- MITRE ATT&CK Tags: {', '.join(context.get('mitre_tags', []))}

LOG EVENT TELEMETRY:
- Hostname: {context.get('hostname', 'N/A')}
- Username: {context.get('username', 'N/A')}
- Source IP: {context.get('source_ip', 'N/A')}
- Destination IP: {context.get('destination_ip', 'N/A')}
- Raw Log Message: {context.get('event_message', 'N/A')}

MATCHED PATTERNS:
{context.get('matched_fields', [])}

Provide your structured SOC threat assessment in the mandated JSON format.
"""
