import hashlib
import unittest
from unittest.mock import patch

import scanner_guard as guard


TARGET = "http://pentagi-effectiveness-target:8000"
LOGIN = '{"username":"alice","password":"test-only-secret"}'
LOGIN_ARGS = [
    "curl", "-sS", "-X", "POST", "-H", "Content-Type: application/json",
    "-d", LOGIN, TARGET + "/api/v1/session",
]


class FixtureAuthenticationGuardTest(unittest.TestCase):
    def run_guard(self, args, attempts=None):
        return guard.command_risk(" ".join(__import__("shlex").quote(x) for x in args), attempts if attempts is not None else set())

    def test_documented_fixture_login_allowed_once(self):
        for username in ("alice", "bob"):
            args = list(LOGIN_ARGS)
            args[args.index(LOGIN)] = LOGIN.replace("alice", username)
            with self.subTest(username=username), patch.dict(guard.FIXTURE_PASSWORD_HASHES, {
                username: hashlib.sha256(b"test-only-secret").hexdigest(),
            }):
                attempts = set()
                self.assertIsNone(self.run_guard(args, attempts))
                self.assertEqual(attempts, {username})
                self.assertEqual(self.run_guard(args, attempts), ("curl_login", "repeat_login_attempt_blocked"))

    def test_unrelated_write_operations_remain_blocked(self):
        with patch.dict(guard.FIXTURE_PASSWORD_HASHES, {
            "alice": hashlib.sha256(b"test-only-secret").hexdigest(),
        }):
            blocked = [
                ["curl", "-X", "POST", "-H", "Content-Type: application/json", "-d", LOGIN, TARGET + "/api/v1/invoices"],
                ["curl", "-X", "PUT", TARGET + "/api/v1/session"],
                ["curl", "-X", "DELETE", TARGET + "/api/v1/invoices/1"],
                ["curl", "-X", "POST", "-H", "Content-Type: application/json", "-d", LOGIN, TARGET + "/api/v1/session?next=/"],
                ["curl", "-X", "POST", "-H", "Content-Type: application/json", "-H", "X-HTTP-Method-Override: DELETE", "-d", LOGIN, TARGET + "/api/v1/session"],
            ]
            for args in blocked:
                with self.subTest(args=args):
                    self.assertIsNotNone(self.run_guard(args))

    def test_invalid_credentials_headers_hosts_and_curl_options_blocked(self):
        bad = [
            ["curl", "-X", "POST", "-H", "Content-Type: application/json", "-d", '{"username":"alice","password":"wrong"}', TARGET + "/api/v1/session"],
            ["curl", "-X", "POST", "-d", LOGIN, TARGET + "/api/v1/session"],
            ["curl", "-X", "POST", "-H", "Content-Type: application/json", "-d", LOGIN, "http://other:8000/api/v1/session"],
            ["curl", "--data-urlencode", LOGIN, TARGET + "/api/v1/session"],
            ["curl", "-X", "POST", "-H", "Content-Type: application/json", "-d", LOGIN, TARGET + "/api/v1/session"],
        ]
        for args in bad:
            with self.subTest(args=args):
                self.assertIsNotNone(self.run_guard(args))

    def test_shell_expansion_interpreters_and_chains_blocked(self):
        for command in (
            "curl -X POST -d \"$LOGIN\" " + TARGET + "/api/v1/session",
            "python3 -c 'print(1)'",
            "curl " + TARGET + "/api/v1/me; curl -X POST " + TARGET + "/api/v1/session",
            "curl " + TARGET + "/api/v1/me | tee /tmp/response",
        ):
            with self.subTest(command=command):
                self.assertIsNotNone(guard.command_risk(command, set()))

    def test_searcher_tools_remain_available_and_are_not_blocked(self):
        names = ("search", "search_answer", "search_result", "search_in_memory", "graphiti_search")
        request = {"tools": [
            {"type": "function", "function": {"name": name, "parameters": {"type": "object"}}}
            for name in names
        ]}
        filtered, removed = guard.restrict_request_tools(request)
        self.assertEqual([x["function"]["name"] for x in filtered["tools"]], list(names))
        self.assertEqual(removed, [])
        for name in names:
            _, events = guard.guard_response({
                "choices": [{"message": {"tool_calls": [{
                    "id": "blocked-search", "type": "function",
                    "function": {"name": name, "arguments": "{}"},
                }]}}]
            })
            self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()
