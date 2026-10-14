"""Unit tests for the pure parts of spend_limit.py. No AWS calls.

Run: python3 -m unittest discover -s tests
"""

import datetime as dt
import importlib.util
import pathlib
import sys
import types
import unittest

# The script imports boto3 at module level. The functions under test never call it.
sys.modules.setdefault("boto3", types.ModuleType("boto3"))
_spec = importlib.util.spec_from_file_location(
    "spend_limit", pathlib.Path(__file__).resolve().parent.parent / "spend_limit.py"
)
sl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sl)

UTC = dt.timezone.utc
HUMAN = [r"^AWSReservedSSO_"]
PRICES = {
    "claude-sonnet-5-5": {"input": 2.4, "output": 12, "cache_read": 0.12, "cache_write": 3},
    "claude-sonnet-5": {"input": 2.4, "output": 12, "cache_read": 0.24, "cache_write": 3},
    "gpt-oss-20b": {"input": 0.084, "output": 0.36},
    "default": {"input": 12, "output": 60, "cache_read": 0.3, "cache_write": 15},
}


class PeriodBounds(unittest.TestCase):
    now = dt.datetime(2026, 10, 14, 17, 30, tzinfo=UTC)  # a Wednesday

    def test_day(self):
        self.assertEqual(
            sl.period_bounds("day", self.now),
            (dt.datetime(2026, 10, 14, tzinfo=UTC), dt.datetime(2026, 10, 15, tzinfo=UTC)),
        )

    def test_week_starts_monday(self):
        self.assertEqual(
            sl.period_bounds("week", self.now),
            (dt.datetime(2026, 10, 12, tzinfo=UTC), dt.datetime(2026, 10, 19, tzinfo=UTC)),
        )

    def test_month_rolls_over_the_year(self):
        dec = dt.datetime(2026, 12, 31, 23, 59, tzinfo=UTC)
        self.assertEqual(
            sl.period_bounds("month", dec),
            (dt.datetime(2026, 12, 1, tzinfo=UTC), dt.datetime(2027, 1, 1, tzinfo=UTC)),
        )


class PrincipalOf(unittest.TestCase):
    def test_identity_center_user_is_human_keyed_by_session(self):
        p = sl.principal_of(
            "arn:aws-us-gov:sts::111122223333:assumed-role/AWSReservedSSO_Dev_abc123/gary.carter", HUMAN, []
        )
        self.assertEqual((p["key"], p["kind"]), ("user:gary.carter", "human"))

    def test_workload_is_keyed_by_role_not_session(self):
        a = sl.principal_of("arn:aws:sts::111122223333:assumed-role/tenant-k2-api/botocore-1", HUMAN, [])
        b = sl.principal_of("arn:aws:sts::111122223333:assumed-role/tenant-k2-api/botocore-2", HUMAN, [])
        self.assertEqual(a["key"], "role:tenant-k2-api")
        self.assertEqual(a["key"], b["key"])
        self.assertEqual(
            a["arns"],
            ["arn:aws:iam::111122223333:role/tenant-k2-api", "arn:aws:iam::111122223333:role/*/tenant-k2-api"],
        )

    def test_iam_user(self):
        p = sl.principal_of("arn:aws:iam::111122223333:user/ci/deployer", HUMAN, [])
        self.assertEqual((p["key"], p["arns"]), ("iam-user:deployer", ["arn:aws:iam::111122223333:user/ci/deployer"]))

    def test_exempt(self):
        arn = "arn:aws:sts::111122223333:assumed-role/break-glass/x"
        self.assertIsNone(sl.principal_of(arn, HUMAN, [r"/break-glass/"]))


class Price(unittest.TestCase):
    def test_longest_key_wins(self):
        row = {"modelId": "us-gov.anthropic.claude-sonnet-5-5", "in_tokens": "1000000", "cache_read_tokens": "1000000"}
        self.assertAlmostEqual(sl.price(row, PRICES), 2.4 + 0.12)

    def test_unknown_model_is_priced_as_default(self):
        self.assertAlmostEqual(sl.price({"modelId": "nvidia.nemotron", "out_tokens": "1000000"}, PRICES), 60)

    def test_missing_cache_rate_falls_back_to_input(self):
        row = {"modelId": "openai.gpt-oss-20b-1:0", "cache_read_tokens": "1000000"}
        self.assertAlmostEqual(sl.price(row, PRICES), 0.084)


class LimitFor(unittest.TestCase):
    now = dt.datetime(2026, 10, 14, 12, tzinfo=UTC)
    defaults = {"human": 50, "workload": 100}

    def test_default_by_kind(self):
        self.assertEqual(sl.limit_for({"key": "role:x", "kind": "workload"}, {}, {}, self.defaults, self.now), 100)

    def test_per_principal_limit(self):
        self.assertEqual(sl.limit_for({"key": "user:a", "kind": "human"}, {"user:a": 20}, {}, self.defaults, self.now), 20)

    def test_override_wins_until_it_expires(self):
        p = {"key": "role:k2", "kind": "workload"}
        live = {"role:k2": {"limit_usd": 500, "until": "2026-10-14T13:00:00Z"}}
        dead = {"role:k2": {"limit_usd": 500, "until": "2026-10-14T11:00:00Z"}}
        self.assertEqual(sl.limit_for(p, {"role:k2": 200}, live, self.defaults, self.now), 500)
        self.assertEqual(sl.limit_for(p, {"role:k2": 200}, dead, self.defaults, self.now), 200)


class DenyStatement(unittest.TestCase):
    until = dt.datetime(2026, 10, 15, tzinfo=UTC)

    def test_human_matches_the_session_and_expires(self):
        st = sl.deny_statement({"key": "user:gary.carter", "kind": "human", "name": "gary.carter"}, self.until)
        self.assertEqual(st["Condition"]["StringLike"], {"aws:userid": "*:gary.carter"})
        self.assertEqual(st["Condition"]["DateLessThan"], {"aws:CurrentTime": "2026-10-15T00:00:00Z"})
        self.assertIn("bedrock-mantle:CreateInference", st["Action"])
        self.assertRegex(st["Sid"], r"^Block[A-Za-z0-9]+$")

    def test_workload_matches_the_role_arn(self):
        p = sl.principal_of("arn:aws:sts::111122223333:assumed-role/tenant-k2-api/s", HUMAN, [])
        st = sl.deny_statement(p, self.until)
        self.assertEqual(st["Condition"]["ArnLike"]["aws:PrincipalArn"], p["arns"])

    def test_sids_differ_for_names_that_differ_only_in_punctuation(self):
        a = sl.deny_statement({"key": "user:a.b", "kind": "human", "name": "a.b"}, self.until)
        b = sl.deny_statement({"key": "user:a-b", "kind": "human", "name": "a-b"}, self.until)
        self.assertNotEqual(a["Sid"], b["Sid"])


if __name__ == "__main__":
    unittest.main()
