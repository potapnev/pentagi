import ast
import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch


PROXY = Path(__file__).with_name("qwen-matched-proxy.py")


def load_functions(*names):
    tree = ast.parse(PROXY.read_text())
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names]
    namespace = {"copy": copy, "json": json, "os": os, "calibration_tool": lambda _: None,
                 "ASSESSMENT_MARKER": "A3AUTH-test-marker"}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(PROXY), "exec"), namespace)
    return namespace


class ProxyGuardTest(unittest.TestCase):
    def test_generation_limit_uses_configured_value_and_default(self):
        configured_limit = load_functions("configured_limit")["configured_limit"]
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(configured_limit("GENERATION_LIMIT", 10), 10)
        with patch.dict(os.environ, {"GENERATION_LIMIT": "12"}, clear=True):
            self.assertEqual(configured_limit("GENERATION_LIMIT", 10), 12)

    def test_budget_ledger_records_generation_limit(self):
        namespace = load_functions("initial_state")
        namespace.update({"GENERATION_LIMIT": 16, "INPUT_LIMIT": 80000,
                          "TARGET_LIMIT": 5, "WALL_LIMIT": 600, "MODE": "baseline"})
        self.assertEqual(namespace["initial_state"]()["generation_limit"], 16)

    def test_marker_gate_allows_only_marked_flow_or_exact_calibration(self):
        funcs = load_functions("assessment_request_allowed")
        allowed = funcs["assessment_request_allowed"]
        foreign = {"messages": [{"role": "user", "content": "other flow"}]}
        marked = {"messages": [{"role": "user", "content": "run A3AUTH-test-marker"}]}
        calibration = {"messages": [{"role": "system", "content": "calibration"}]}
        funcs["calibration_tool"] = lambda request: "fixture" if request is calibration else None
        self.assertFalse(allowed(foreign, "A3AUTH-test-marker"))
        self.assertFalse(allowed({"messages": None}, "A3AUTH-test-marker"))
        self.assertTrue(allowed(marked, "A3AUTH-test-marker"))
        self.assertTrue(allowed(calibration, "A3AUTH-test-marker"))
        self.assertTrue(allowed(foreign, ""))

    def test_marker_propagates_only_across_internal_agent_handoffs(self):
        propagate = load_functions("propagate_assessment_marker")["propagate_assessment_marker"]
        response = {"choices": [{"message": {"tool_calls": [
            {"id": "p1", "function": {"name": "pentester", "arguments": '{"question":"authenticate"}'}},
            {"id": "s1", "function": {"name": "search", "arguments": '{"question":"lookup"}'}},
            {"id": "t1", "function": {"name": "terminal", "arguments": '{"input":"curl"}'}},
        ]}}]}
        updated, events = propagate(response)
        calls = updated["choices"][0]["message"]["tool_calls"]
        self.assertEqual({event["tool"] for event in events}, {"pentester", "search"})
        for call in calls[:2]:
            self.assertIn("A3AUTH-test-marker", json.loads(call["function"]["arguments"])["question"])
        self.assertEqual(json.loads(calls[2]["function"]["arguments"]), {"input": "curl"})
        self.assertNotIn("A3AUTH-test-marker", json.dumps(response))
        second, second_events = propagate(updated)
        self.assertEqual(second, updated)
        self.assertEqual(second_events, [])


if __name__ == "__main__":
    unittest.main()
