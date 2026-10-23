"""Bedrock spend limit per principal, for one AWS account.

Runs inside SSM Automation (aws:executeScript) on a schedule. Each run:

1. Prices every principal's Bedrock tokens for the current period, per model, from the
   invocation logs in each Region.
2. Drops blocks whose time is up. That principal's spend then counts again from the
   moment the block ended, so the usage that caused the block does not cause another.
3. Sends a warning when a principal passes a warning threshold, once per threshold
   per period: to the SNS topic, and through SES when an email is configured.
4. Blocks each principal over its limit with a deny statement in one managed policy.
   Each deny ends by itself through aws:CurrentTime, even if this script stops.

Principals:
  human     a role session whose role name matches a human pattern (by default
            AWSReservedSSO_*). Keyed and blocked by session name, which Identity
            Center sets to the user name.
  workload  any other role. Keyed and blocked by role, because workload session names
            change with every pod or task.
  iam user  keyed and blocked by the user ARN.
"""

import datetime as dt
import hashlib
import json
import re
import time

import boto3

SID_PREFIX = "Block"
PLACEHOLDER = {
    "Sid": "NoBlocks",
    "Effect": "Deny",
    "Action": "bedrock:InvokeModel",
    "Resource": "*",
    "Condition": {"StringEquals": {"aws:userid": "no-principal-has-this-id"}},
}
INFERENCE_ACTIONS = [
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream",
    "bedrock:Converse",
    "bedrock:ConverseStream",
    "bedrock:CallWithBearerToken",
    "bedrock:StartAsyncInvoke",
    "bedrock:CreateModelInvocationJob",
    "bedrock-mantle:CreateInference",
    "bedrock-mantle:CallWithBearerToken",
]
QUERY = """
fields identity.arn as principal, modelId,
       input.inputTokenCount as i, output.outputTokenCount as o,
       input.cacheReadInputTokenCount as cr, input.cacheWriteInputTokenCount as cw
| filter ispresent(principal)
| stats sum(i) as in_tokens, sum(o) as out_tokens,
        sum(cr) as cache_read_tokens, sum(cw) as cache_write_tokens by principal, modelId
"""


# --------------------------------------------------------------------------------------
# Pure functions. Tested in tests/test_spend_limit.py without AWS.
# --------------------------------------------------------------------------------------


def period_bounds(period, now):
    """Start and end of the period that contains now, in UTC."""
    day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "day":
        return day, day + dt.timedelta(days=1)
    if period == "week":
        start = day - dt.timedelta(days=day.weekday())
        return start, start + dt.timedelta(days=7)
    if period == "month":
        start = day.replace(day=1)
        end = (start + dt.timedelta(days=32)).replace(day=1)
        return start, end
    raise ValueError(f"unknown period {period!r}")


def usd(x):
    """Dollars for a note: cents from $1 up, four places below, so small limits stay readable."""
    return f"${x:,.2f}" if abs(x) >= 1 else f"${x:.4f}"


def notice(notes, pacing, period, spend, exclude=()):
    """The text of a notice: the notes, the pacing, and each principal's spend.

    notes are (principal key, text) pairs. Notes and spend of the principals in exclude
    are left out. Returns None when no note is left.
    """
    texts = [text for key, text in notes if key not in exclude]
    if not texts:
        return None
    ranked = sorted(spend.items(), key=lambda kv: -kv[1])
    return "\n".join(
        texts
        + ([pacing] if pacing else [])
        + ["", f"Spend this {period} (USD):"]
        + [f"  {k}: {usd(v)}" for k, v in ranked if k not in exclude]
    )


def business_days(now, holidays):
    """Monday to Friday days in now's UTC month, less the holidays that fall on them."""
    first = now.date().replace(day=1)
    following = (first + dt.timedelta(days=32)).replace(day=1)
    days = (first + dt.timedelta(days=n) for n in range((following - first).days))
    return sum(1 for d in days if d.weekday() < 5 and d not in holidays)


def paced_limit(monthly_usd, now, holidays):
    """A monthly budget as a daily limit: the budget over the month's business days.

    Every day gets this limit, weekends and holidays included. They are left out of
    the count so that a month of working days spends the budget.
    """
    return monthly_usd / business_days(now, holidays)


def principal_of(arn, human_patterns, exempt_patterns):
    """Classify the caller in an invocation log record.

    Returns None for a caller the limit does not cover, else a dict with the key that
    spend is summed under, the kind, and the parts the deny statement needs.
    """
    if any(re.search(p, arn) for p in exempt_patterns):
        return None
    m = re.match(r"^arn:([^:]+):sts::(\d+):assumed-role/([^/]+)/(.+)$", arn)
    if m:
        partition, account, role, session = m.groups()
        if any(re.search(p, role) for p in human_patterns):
            return {"key": f"user:{session}", "kind": "human", "name": session}
        return {
            "key": f"role:{role}",
            "kind": "workload",
            "name": role,
            "arns": [
                f"arn:{partition}:iam::{account}:role/{role}",
                f"arn:{partition}:iam::{account}:role/*/{role}",
            ],
        }
    m = re.match(r"^arn:[^:]+:iam::\d+:user/(?:.*/)?([^/]+)$", arn)
    if m:
        return {"key": f"iam-user:{m.group(1)}", "kind": "workload", "name": m.group(1), "arns": [arn]}
    return None


def price(row, prices):
    """USD for one row of the query: tokens of one principal for one model."""
    model = row.get("modelId", "")
    rate = prices["default"]
    for key in sorted(prices, key=len, reverse=True):
        if key != "default" and key in model:
            rate = prices[key]
            break
    usd = 0.0
    for field, kind in (
        ("in_tokens", "input"),
        ("out_tokens", "output"),
        ("cache_read_tokens", "cache_read"),
        ("cache_write_tokens", "cache_write"),
    ):
        tokens = float(row.get(field) or 0)
        usd += tokens * rate.get(kind, rate["input"]) / 1_000_000
    return usd


def limit_for(principal, limits, overrides, defaults, now):
    """The limit in USD: an unexpired override, else a per-principal limit, else the default."""
    o = overrides.get(principal["key"])
    if o and parse(o["until"]) > now:
        return float(o["limit_usd"])
    if principal["key"] in limits:
        return float(limits[principal["key"]])
    return float(defaults[principal["kind"]])


def deny_statement(principal, until):
    digest = hashlib.sha1(principal["key"].encode()).hexdigest()[:8]
    sid = SID_PREFIX + re.sub(r"[^A-Za-z0-9]", "", principal["name"].title())[:48] + digest
    condition = {"DateLessThan": {"aws:CurrentTime": until.strftime("%Y-%m-%dT%H:%M:%SZ")}}
    if principal["kind"] == "human":
        condition["StringLike"] = {"aws:userid": "*:" + principal["name"]}
    else:
        condition["ArnLike"] = {"aws:PrincipalArn": principal["arns"]}
    return {"Sid": sid, "Effect": "Deny", "Action": INFERENCE_ACTIONS, "Resource": "*", "Condition": condition}


def block_end(statement):
    return parse(statement["Condition"]["DateLessThan"]["aws:CurrentTime"])


def parse(s):
    if isinstance(s, dt.datetime):
        return s
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


# --------------------------------------------------------------------------------------
# The run.
# --------------------------------------------------------------------------------------


def handler(events, context):
    now = dt.datetime.now(dt.timezone.utc)
    cfg = {k: events[k] for k in events}
    dry_run = str(cfg.get("DryRun", "false")).lower() == "true"
    period_start, period_end = period_bounds(cfg["Period"], now)
    block_minutes = int(cfg["BlockMinutes"])
    human = float(cfg["HumanLimitUsd"])
    pacing = ""
    if cfg.get("MonthlyBudgetUsd"):
        holidays = {dt.date.fromisoformat(d) for d in json.loads(cfg.get("HolidaysJson") or "[]")}
        human = paced_limit(float(cfg["MonthlyBudgetUsd"]), now, holidays)
        pacing = (
            f"Human daily limit: {usd(human)}, {usd(float(cfg['MonthlyBudgetUsd']))} a month"
            f" over {business_days(now, holidays)} business days"
        )
    workload = float(cfg["WorkloadLimitUsd"]) if cfg.get("WorkloadLimitUsd") else 2 * human
    defaults = {"human": human, "workload": workload}
    limits = json.loads(cfg["LimitsJson"])
    prices = json.loads(cfg["PricesJson"])
    warn_at = sorted(float(x) for x in json.loads(cfg["WarnAtJson"]))
    human_patterns = json.loads(cfg["HumanPatternsJson"])
    exempt_patterns = json.loads(cfg["ExemptPatternsJson"])
    regions = cfg["Regions"].split(",")

    ssm = boto3.client("ssm")
    iam = boto3.client("iam")
    overrides = _read_json_parameter(ssm, cfg["OverrideParameter"])
    state = _read_json_parameter(ssm, cfg["StateParameter"])
    if state.get("period") != period_start.isoformat():
        state = {"period": period_start.isoformat(), "principals": {}}
    pstate = state["principals"]

    statements = _policy_statements(iam, cfg["PolicyArn"])
    blocks = {s["Sid"]: s for s in statements if s.get("Sid", "").startswith(SID_PREFIX)}
    notes = []

    # Blocks that ended: drop them, and count that principal from the end of the block.
    for sid, st in list(blocks.items()):
        end = block_end(st)
        if end <= now:
            del blocks[sid]
            key = next((k for k, v in pstate.items() if v.get("sid") == sid), None)
            if key:
                pstate[key].update({"since": end.isoformat(), "sid": None, "warned": []})
            notes.append((key, f"unblocked {key or sid}, block ended {end:%Y-%m-%d %H:%M} UTC"))

    # Spend this period, per principal, from the start of their window.
    rows = []
    for region in regions:
        rows += [(region, r) for r in _query(region, cfg["LogGroup"], period_start, now)]
    since = {k: parse(v["since"]) for k, v in pstate.items() if v.get("since")}
    late = {k: t for k, t in since.items() if t > period_start}

    spend, who = {}, {}
    for _, row in rows:
        p = principal_of(row["principal"], human_patterns, exempt_patterns)
        if not p or p["key"] in late:
            continue
        who[p["key"]] = p
        spend[p["key"]] = spend.get(p["key"], 0.0) + price(row, prices)
    for key, start in late.items():
        for region in regions:
            for row in _query(region, cfg["LogGroup"], start, now):
                p = principal_of(row["principal"], human_patterns, exempt_patterns)
                if p and p["key"] == key:
                    who[key] = p
                    spend[key] = spend.get(key, 0.0) + price(row, prices)

    # Warnings and new blocks.
    for key, spent in sorted(spend.items()):
        p = who[key]
        limit = limit_for(p, limits, overrides, defaults, now)
        entry = pstate.setdefault(key, {"warned": [], "sid": None})
        for frac in warn_at:
            if spent >= frac * limit and frac not in entry["warned"] and spent < limit:
                entry["warned"].append(frac)
                notes.append((key, f"warning: {key} spent {usd(spent)}, {spent / limit:.0%} of its {usd(limit)} limit"))
        if spent >= limit and not entry.get("sid"):
            until = now + dt.timedelta(minutes=block_minutes) if block_minutes else period_end
            st = deny_statement(p, until)
            blocks[st["Sid"]] = st
            entry["sid"] = st["Sid"]
            notes.append((key, f"blocked {key} until {until:%Y-%m-%d %H:%M} UTC: spent {usd(spent)}, limit {usd(limit)}"))

    new_statements = list(blocks.values()) or [PLACEHOLDER]
    policy_changed = new_statements != statements
    if not dry_run:
        if policy_changed:
            _write_policy(iam, cfg["PolicyArn"], new_statements)
        _write_json_parameter(ssm, cfg["StateParameter"], state)
        subject = f"Bedrock spend limit: {cfg['Name']}"[:100]
        message = notice(notes, pacing, cfg["Period"], spend)
        if message and cfg.get("TopicArn"):
            boto3.client("sns").publish(TopicArn=cfg["TopicArn"], Subject=subject, Message=message)
        email = json.loads(cfg.get("EmailJson") or "null")
        body = email and notice(notes, pacing, cfg["Period"], spend, set(email["exclude"]))
        if body:
            _send_email(email, subject, body)

    return {
        "dryRun": dry_run,
        "policyChanged": policy_changed,
        "humanLimitUsd": round(human, 4),
        "notes": [text for _, text in notes],
        "spend": {k: round(v, 4) for k, v in spend.items()},
    }


def _query(region, log_group, start, end):
    logs = boto3.client("logs", region_name=region)
    qid = logs.start_query(
        logGroupName=log_group,
        startTime=int(start.timestamp()),
        endTime=int(end.timestamp()) + 1,
        queryString=QUERY,
        limit=10000,
    )["queryId"]
    while True:
        res = logs.get_query_results(queryId=qid)
        if res["status"] in ("Complete", "Failed", "Cancelled", "Timeout"):
            break
        time.sleep(2)
    if res["status"] != "Complete":
        raise RuntimeError(f"Logs Insights query in {region} ended {res['status']}")
    return [{f["field"]: f["value"] for f in r} for r in res["results"]]


def _send_email(email, subject, body):
    boto3.client("sesv2").send_email(
        FromEmailAddress=email["from"],
        Destination={"ToAddresses": email["to"], "BccAddresses": email["bcc"]},
        ReplyToAddresses=email["reply_to"],
        Content={"Simple": {
            "Subject": {"Data": subject, "Charset": "UTF-8"},
            "Body": {"Text": {"Data": body, "Charset": "UTF-8"}},
        }},
    )


def _policy_statements(iam, arn):
    version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
    doc = iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]["Document"]
    if isinstance(doc, str):
        doc = json.loads(doc)
    st = doc["Statement"]
    return [s for s in (st if isinstance(st, list) else [st]) if s.get("Sid") != PLACEHOLDER["Sid"]] or [PLACEHOLDER]


def _write_policy(iam, arn, statements):
    # A managed policy keeps at most five versions. Make room by deleting the oldest
    # version that is not the default.
    versions = iam.list_policy_versions(PolicyArn=arn)["Versions"]
    if len(versions) >= 5:
        old = sorted((v for v in versions if not v["IsDefaultVersion"]), key=lambda v: v["CreateDate"])[0]
        iam.delete_policy_version(PolicyArn=arn, VersionId=old["VersionId"])
    iam.create_policy_version(
        PolicyArn=arn,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        SetAsDefault=True,
    )


def _read_json_parameter(ssm, name):
    return json.loads(ssm.get_parameter(Name=name)["Parameter"]["Value"] or "{}")


def _write_json_parameter(ssm, name, value):
    ssm.put_parameter(Name=name, Value=json.dumps(value), Type="String", Tier="Intelligent-Tiering", Overwrite=True)
