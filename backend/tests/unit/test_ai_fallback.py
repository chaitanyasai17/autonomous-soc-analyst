"""Unit tests for AI Provider abstraction and offline Heuristic fallback."""

import asyncio
import unittest
from app.ai.providers import HeuristicAIProvider


class TestAIFallback(unittest.TestCase):
    def test_heuristic_provider_generation(self):
        provider = HeuristicAIProvider()
        context = {
            "rule_title": "Suspicious PowerShell Download Cradle",
            "severity": "high",
            "rule_category": "process_creation",
            "username": "admin",
            "hostname": "WORKSTATION-01",
            "matched_fields": [{"field": "CommandLine", "value": "powershell -enc ..."}],
            "mitre_tags": ["attack.execution", "attack.t1059.001"],
        }
        res = asyncio.run(
            provider.generate_threat_analysis(prompt="Analyze this", system_prompt="", context=context)
        )
        self.assertIn("threat_summary", res)
        self.assertIn("attack_narrative", res)
        self.assertEqual(res["false_positive_likelihood"], "low")
        self.assertGreaterEqual(res["confidence"], 0.7)
        self.assertGreater(len(res["recommended_actions"]), 0)
        self.assertIn("heuristic", res["provider_used"])

    def test_heuristic_detects_test_false_positive(self):
        provider = HeuristicAIProvider()
        context = {
            "rule_title": "Web Attack Indicator",
            "severity": "medium",
            "event_message": "Healthcheck probe test endpoint /health",
            "username": "system",
            "hostname": "WEB-SRV",
        }
        res = asyncio.run(
            provider.generate_threat_analysis(prompt="Analyze", system_prompt="", context=context)
        )
        self.assertEqual(res["false_positive_likelihood"], "high")


if __name__ == "__main__":
    unittest.main()
