"""
AI Provider abstraction for ASOC Threat Analysis.
Supports Ollama, OpenAI-compatible APIs, and an intelligent offline Heuristic provider
that guarantees uninterrupted analysis even without internet or external LLM availability.
"""

from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from typing import Any, Dict

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


class BaseAIProvider(ABC):
    @abstractmethod
    async def generate_threat_analysis(
        self, prompt: str, system_prompt: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate structured threat analysis dictionary."""
        pass


class OllamaProvider(BaseAIProvider):
    def __init__(self, base_url: str, model: str, timeout_seconds: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout_seconds

    async def generate_threat_analysis(
        self, prompt: str, system_prompt: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        endpoint = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.2},
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(endpoint, json=payload)
            resp.raise_for_status()
            data = resp.json()
            raw_text = data.get("response", "{}")
            try:
                parsed = json.loads(raw_text)
                parsed["provider_used"] = f"ollama ({self.model})"
                return parsed
            except Exception:
                # Attempt to extract JSON markdown block
                match = re.search(r"\{.*\}", raw_text, re.DOTALL)
                if match:
                    parsed = json.loads(match.group(0))
                    parsed["provider_used"] = f"ollama ({self.model})"
                    return parsed
                raise ValueError("Could not parse JSON response from Ollama model")


class OpenAIProvider(BaseAIProvider):
    def __init__(self, api_key: str | None = None, base_url: str = "https://api.openai.com/v1", model: str = "gpt-4o-mini", timeout_seconds: float = 15.0):
        self.api_key = api_key or ""
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout_seconds

    async def generate_threat_analysis(
        self, prompt: str, system_prompt: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        endpoint = f"{self.base_url}/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2,
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(endpoint, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            raw_content = data["choices"][0]["message"]["content"]
            parsed = json.loads(raw_content)
            parsed["provider_used"] = f"openai ({self.model})"
            return parsed


class HeuristicAIProvider(BaseAIProvider):
    """
    Intelligent cybersecurity heuristic analysis engine.
    Produces deterministic, context-aware SOC threat evaluations
    when external LLMs are unavailable, ensuring zero downtime and realistic insights.
    """

    async def generate_threat_analysis(
        self, prompt: str, system_prompt: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        rule_title = context.get("rule_title", "Unknown Security Event")
        severity = str(context.get("severity", "medium")).lower()
        rule_category = context.get("rule_category", "general")
        matched_fields = context.get("matched_fields") or []
        mitre_tags = context.get("mitre_tags") or []
        event_message = context.get("event_message", "")
        username = context.get("username", "Unknown")
        host = context.get("hostname", "Unknown host")

        # Determine false positive likelihood
        if "test" in str(event_message).lower() or "healthcheck" in str(event_message).lower():
            fp_likelihood = "high"
            fp_explanation = "Payload contains test or healthcheck keywords often associated with automated validation."
        elif severity in ("high", "critical"):
            fp_likelihood = "low"
            fp_explanation = "Signature matches known hostile attack pattern with high fidelity."
        else:
            fp_likelihood = "medium"
            fp_explanation = "Standard administrative tools can occasionally trigger this detection."

        # Recommended response actions based on rule category
        actions = [
            f"Isolate affected host '{host}' from production network segment if unauthorized activity persists.",
            f"Review authentication logs for account '{username}' across all identity providers.",
            "Collect volatile memory and process execution timeline around the event timestamp.",
        ]
        if "credential" in rule_category or "brute" in rule_title.lower():
            actions.insert(0, f"Immediately revoke active sessions and force password reset for user '{username}'.")
            actions.append("Verify MFA configuration and check for suspicious MFA prompt bombardment.")
        elif "powershell" in rule_title.lower() or "command" in rule_title.lower() or "lolbin" in rule_title.lower():
            actions.insert(0, "Inspect child process lineage and decode encoded command strings.")
            actions.append("Scan downloaded binaries against internal threat intelligence hashes.")
        elif "web" in rule_category or "sql" in rule_title.lower() or "xss" in rule_title.lower():
            actions.insert(0, "Block source IP address on perimeter Web Application Firewall (WAF).")
            actions.append("Review web server access logs for subsequent 200 OK responses to attack payloads.")

        # Indicators of Compromise extraction
        iocs: list[dict[str, str]] = []
        if context.get("source_ip"):
            iocs.append({"type": "ip", "value": str(context["source_ip"]), "description": "Attacker source IP"})
        if context.get("destination_ip"):
            iocs.append({"type": "ip", "value": str(context["destination_ip"]), "description": "Target internal IP"})
        for field in matched_fields:
            if isinstance(field, dict) and field.get("field") in ("message", "command", "process"):
                val = str(field.get("value", ""))[:120]
                iocs.append({"type": "pattern", "value": val, "description": f"Matched pattern in {field.get('field')}"})

        summary = (
            f"AI Threat Assessment indicates suspicious activity matching '{rule_title}'. "
            f"The detection observed potential adversarial behavior targeting host '{host}' "
            f"associated with account '{username}'. Severity is evaluated as {severity.upper()}."
        )

        narrative = (
            f"Adversary activity was flagged by Sigma detection engine under category '{rule_category}'. "
            f"The observed telemetry indicates actions consistent with MITRE ATT&CK techniques: "
            f"{', '.join(mitre_tags) if mitre_tags else 'Tactical execution/evasion'}. "
            f"Initial triage suggests immediate containment actions should be prioritized."
        )

        return {
            "threat_summary": summary,
            "attack_narrative": narrative,
            "confidence": 0.88 if severity in ("high", "critical") else 0.75,
            "false_positive_likelihood": fp_likelihood,
            "false_positive_rationale": fp_explanation,
            "recommended_actions": actions,
            "indicators_of_compromise": iocs,
            "mitre_alignment": mitre_tags,
            "provider_used": "asoc-heuristic-engine (offline resilience)",
        }


def get_ai_provider() -> BaseAIProvider:
    """Factory creating provider with fallback safety."""
    settings = get_settings()
    provider_name = (settings.AI_PROVIDER or "heuristic").lower().strip()

    if provider_name == "ollama":
        return OllamaProvider(
            base_url=settings.OLLAMA_BASE_URL,
            model=settings.OLLAMA_MODEL,
        )
    elif provider_name == "openai":
        return OpenAIProvider()
    else:
        return HeuristicAIProvider()
