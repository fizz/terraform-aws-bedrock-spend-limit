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


class Pacing(unittest.TestCase):
    october = dt.datetime(2026, 10, 14, 17, 30, tzinfo=UTC)  # 22 weekdays
    columbus = {dt.date(2026, 10, 12)}

    def test_weekdays_only(self):
        self.assertEqual(sl.business_days(self.october, set()), 22)

    def test_holiday_on_a_weekday_is_not_a_business_day(self):
        self.assertEqual(sl.business_days(self.october, self.columbus), 21)

    def test_holiday_on_a_weekend_changes_nothing(self):
        self.assertEqual(sl.business_days(self.october, {dt.date(2026, 10, 10)}), 22)

    def test_holidays_in_other_months_are_ignored(self):
        self.assertEqual(sl.business_days(self.october, {dt.date(2026, 11, 26)}), 22)

    def test_december_rolls_over_the_year(self):
        december = dt.datetime(2026, 12, 31, 23, 59, tzinfo=UTC)
        self.assertEqual(sl.business_days(december, {dt.date(2026, 12, 25)}), 22)

    def test_paced_limit_spreads_the_budget(self):
        self.assertAlmostEqual(sl.paced_limit(250, self.october, self.columbus), 250 / 21)


class Usd(unittest.TestCase):
    def test_cents_from_a_dollar_up(self):
        self.assertEqual(sl.usd(250), "$250.00")
        self.assertEqual(sl.usd(1234.5), "$1,234.50")

    def test_four_places_below_a_dollar(self):
        self.assertEqual(sl.usd(0.0238), "$0.0238")
        self.assertEqual(sl.usd(0.0731), "$0.0731")


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



class Notice(unittest.TestCase):
    notes = [
        ("user:gary", "warning: user:gary spent $40.00, 80% of its $50.00 limit"),
        ("user:test", "blocked user:test until 2026-10-15 00:00 UTC: spent $5.10, limit $5.00"),
    ]
    spend = {"user:test": 5.1, "user:gary": 40.0, "user:testing": 1.0}

    def test_every_note_and_spend_ranked_by_amount(self):
        self.assertEqual(
            sl.notice(self.notes, "", "day", self.spend).split("\n"),
            [
                "warning: user:gary spent $40.00, 80% of its $50.00 limit",
                "blocked user:test until 2026-10-15 00:00 UTC: spent $5.10, limit $5.00",
                "",
                "Spend this day (USD):",
                "  user:gary: $40.00",
                "  user:test: $5.10",
                "  user:testing: $1.00",
            ],
        )

    def test_pacing_follows_the_notes(self):
        text = sl.notice(self.notes[:1], "Human daily limit: $50.00", "day", {})
        self.assertEqual(text.split("\n")[1], "Human daily limit: $50.00")

    def test_excluded_principal_is_left_out_by_key(self):
        text = sl.notice(self.notes, "", "day", self.spend, {"user:test"})
        self.assertNotIn("user:test ", text)
        self.assertNotIn("user:test:", text)
        self.assertIn("user:testing: $1.00", text)

    def test_nothing_to_send_when_only_excluded_notes(self):
        self.assertIsNone(sl.notice(self.notes[1:], "", "day", self.spend, {"user:test"}))

    def test_nothing_to_send_without_notes(self):
        self.assertIsNone(sl.notice([], "pacing", "day", self.spend))

    def test_unblock_by_sid_alone_is_never_excluded(self):
        notes = [(None, "unblocked BlockAbc, block ended 2026-10-15 00:00 UTC")]
        self.assertIsNotNone(sl.notice(notes, "", "day", {}, {"user:test"}))


if __name__ == "__main__":
    unittest.main()
