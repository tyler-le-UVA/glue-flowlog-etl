"""
Lambda: flowlogs-daily-report  (milestone 7, v2)

1. Picks a report date: event {"dt": "YYYY-MM-DD"} if given, else the latest dt
   in flowlogs_db.findings.
2. Queries the findings for that date with Athena.
3. PRE-PROCESSES in code (so the model can't get these wrong):
     - splits findings into known-asset activity / external activity / background
     - writes the background-noise line itself, with the real count
     - picks the single most important external finding
4. Sends the structured input to Amazon Bedrock (Converse API).
5. VALIDATES the report in code: every IP/CIDR must exist in the input; flags
   unsupported claims and leftover placeholders. On problems, asks the model
   once to fix them; if problems remain, the email carries a warning.
6. Saves the report, the exact model input, and the validation result to S3.
7. Emails the report through SNS.

Environment variables:
  WORKGROUP      flowlogs-wg
  DATABASE       flowlogs_db
  MODEL_ID       Bedrock model or inference-profile ID (e.g. us.amazon.nova-2-lite-...)
  TOPIC_ARN      arn:aws:sns:us-east-1:<acct>:glue-flowlog-etl-alerts
  REPORT_BUCKET  glue-flowlog-etl-curated-<acct>-us-east-1
  REPORT_PREFIX  reports/
  KNOWN_ASSETS   "ip=description; ip=description"
  MAX_FINDINGS   60
"""
import datetime
import json
import os
import re
import time

import boto3

athena = boto3.client("athena")
bedrock = boto3.client("bedrock-runtime")
s3 = boto3.client("s3")
sns = boto3.client("sns")

WORKGROUP = os.environ["WORKGROUP"]
DATABASE = os.environ.get("DATABASE", "flowlogs_db")
MODEL_ID = os.environ["MODEL_ID"]
TOPIC_ARN = os.environ["TOPIC_ARN"]
REPORT_BUCKET = os.environ["REPORT_BUCKET"]
REPORT_PREFIX = os.environ.get("REPORT_PREFIX", "reports/")
KNOWN_ASSETS_RAW = os.environ.get("KNOWN_ASSETS", "")
MAX_FINDINGS = int(os.environ.get("MAX_FINDINGS", "60"))

SEVERITY_RANK = {"high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_ORDER_SQL = ("CASE severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                      "WHEN 'low' THEN 3 ELSE 4 END")

IP_OR_CIDR = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")
RISKY_TERMS = ["exfiltrat", "compromis", "malware", "breach", "intrusion"]
PLACEHOLDERS = [" N /24", "<", "{"]

SYSTEM_PROMPT = """You are a security analyst writing a daily network-security report \
from AWS VPC Flow Log detections.

The input is already organized for you. Follow these rules exactly:
1. Use ONLY the information provided. Never invent IP addresses, subnets, counts, \
organization names, malware names, or attack attribution.
2. "Notable activity" covers ONLY the items under EXTERNAL FINDINGS.
3. "Expected or benign activity" covers ONLY the items under KNOWN-ASSET ACTIVITY, \
plus the BACKGROUND NOISE line copied exactly as given.
4. The Summary must be built around the MOST IMPORTANT EXTERNAL FINDING.
5. When a finding gives a percentage share (e.g. "Top /24: X (76.7% of the hour)"), \
keep the percentage. Never attribute the full count to the top source.
6. Rejected traffic means a security group blocked it. Do not describe anything as a \
compromise, intrusion, breach, malware, or data exfiltration, and do not claim the \
absence of those either - these detections do not measure them.
7. Recommended actions must name specific IPs, subnets, or hosts from the input. \
No generic advice such as "continue monitoring".
8. Plain text with these headings: Summary, Notable activity, Expected or benign \
activity, Recommended actions, Data notes. Under 400 words."""


def log(msg):
    print(f"[daily_report] {msg}")


def parse_known_assets(raw):
    assets = {}
    for part in raw.split(";"):
        if "=" in part:
            ip, desc = part.split("=", 1)
            assets[ip.strip()] = desc.strip()
    return assets


KNOWN_ASSETS = parse_known_assets(KNOWN_ASSETS_RAW)


def run_query(sql):
    """Run an Athena query and return a list of dicts (column -> string value)."""
    qid = athena.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={"Database": DATABASE},
        WorkGroup=WORKGROUP,
    )["QueryExecutionId"]
    while True:
        status = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
        if status["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(1)
    if status["State"] != "SUCCEEDED":
        raise RuntimeError(f"Athena query {status['State']}: {status.get('StateChangeReason')}")

    rows, header = [], None
    for page in athena.get_paginator("get_query_results").paginate(QueryExecutionId=qid):
        for r in page["ResultSet"]["Rows"]:
            values = [c.get("VarCharValue") for c in r["Data"]]
            if header is None:
                header = values
                continue
            rows.append(dict(zip(header, values)))
    return rows


def resolve_date(event):
    """Manual runs pass {"dt": ...}. Automatic runs report on YESTERDAY (UTC),
    the most recent COMPLETE day."""
    dt = (event or {}).get("dt")
    if not dt:
        dt = (datetime.datetime.utcnow().date() - datetime.timedelta(days=1)).isoformat()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", dt):  # also blocks SQL injection
        raise ValueError(f"Invalid report date: {dt!r}")
    return dt


def already_reported(dt):
    resp = s3.list_objects_v2(Bucket=REPORT_BUCKET, Prefix=f"{REPORT_PREFIX}dt={dt}/", MaxKeys=1)
    return resp.get("KeyCount", 0) > 0


# -----------------------------------------------------------------------------
# Pre-processing: decisions made in code, not by the model
# -----------------------------------------------------------------------------
def organize(findings, counts):
    known, external = [], []
    for f in findings:
        if f["severity"] == "info":
            continue                      # summarized as one background line below
        if f["entity"] in KNOWN_ASSETS:
            known.append(f)
        else:
            external.append(f)
    external.sort(key=lambda f: SEVERITY_RANK.get(f["severity"], 9))

    infra_count = sum(int(c["n"]) for c in counts if c["finding_type"] == "scanning_infrastructure")
    background = (f"{infra_count} /24 networks of mass-scanning infrastructure (info) touched "
                  f"the lab hosts; this is normal internet background noise."
                  if infra_count else "No mass-scanning infrastructure was detected.")

    most_important = external[0] if external else None
    return known, external, background, most_important


def build_prompt(dt, counts, known, external, background, most_important):
    def lines(items):
        return "\n".join(
            f"- [{f['severity']}] {f['finding_type']}: {f['description']}" for f in items
        ) or "(none)"

    assets = "\n".join(f"- {ip} = {desc}" for ip, desc in KNOWN_ASSETS.items()) or "(none provided)"
    count_lines = "\n".join(f"- {c['finding_type']} / {c['severity']}: {c['n']}" for c in counts)
    top = most_important["description"] if most_important else "(no external findings)"

    return f"""Report date (UTC): {dt}

KNOWN ASSETS:
{assets}

MOST IMPORTANT EXTERNAL FINDING (build the Summary around this):
{top}

EXTERNAL FINDINGS (for "Notable activity", highest severity first):
{lines(external)}

KNOWN-ASSET ACTIVITY (for "Expected or benign activity" only):
{lines(known)}

BACKGROUND NOISE (copy this line exactly into "Expected or benign activity"):
{background}

FINDING COUNTS (for reference):
{count_lines}

Write the report now."""


# -----------------------------------------------------------------------------
# Validation: check the model's output in code
# -----------------------------------------------------------------------------
def validate(report, prompt, required_entities):
    issues = []
    missing = [e for e in required_entities if e not in report]
    if missing:
        issues.append(f"omits these external findings: {', '.join(missing)}")
    allowed = set(IP_OR_CIDR.findall(prompt))
    unknown = sorted(set(IP_OR_CIDR.findall(report)) - allowed)
    if unknown:
        issues.append(f"mentions IPs/subnets not present in the input: {', '.join(unknown)}")
    lower = report.lower()
    risky = [t for t in RISKY_TERMS if t in lower]
    if risky:
        issues.append(f"uses unsupported terms ({', '.join(risky)}); these detections do not measure them")
    left = [p.strip() for p in PLACEHOLDERS if p in report]
    if left:
        issues.append(f"contains template placeholders: {', '.join(left)}")
    return issues


def converse(messages):
    resp = bedrock.converse(
        modelId=MODEL_ID,
        system=[{"text": SYSTEM_PROMPT}],
        messages=messages,
        inferenceConfig={"maxTokens": 1200, "temperature": 0.2},
    )
    return resp["output"]["message"]["content"][0]["text"], resp.get("usage", {})


def lambda_handler(event, context):
    forced = bool((event or {}).get("dt"))
    dt = resolve_date(event)
    log(f"report date={dt} forced={forced}")

    # Automatic runs send each day's report once (the pipeline may run every 6 hours)
    if not forced and already_reported(dt):
        log(f"report for {dt} already exists; skipping")
        return {"dt": dt, "skipped": "already reported"}

    counts = run_query(
        f"SELECT finding_type, severity, count(*) AS n FROM findings "
        f"WHERE dt = '{dt}' GROUP BY 1, 2 ORDER BY 1, 2")
    total = sum(int(c["n"]) for c in counts)
    log(f"findings for {dt}: {total}")

    subject = f"Flow log security report - {dt}"
    run_ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    base_key = f"{REPORT_PREFIX}dt={dt}/{run_ts}"

    if total == 0:
        message = f"No findings were detected for {dt}."
        # Save it too, so quiet days are recorded and not re-sent
        s3.put_object(Bucket=REPORT_BUCKET, Key=f"{base_key}/report.md",
                      Body=message.encode("utf-8"), ContentType="text/markdown")
        sns.publish(TopicArn=TOPIC_ARN, Subject=subject, Message=message)
        return {"dt": dt, "findings": 0}

    findings = run_query(
        f"SELECT severity, finding_type, entity, entity_type, target, description "
        f"FROM findings WHERE dt = '{dt}' AND severity <> 'info' "
        f"ORDER BY {SEVERITY_ORDER_SQL}, finding_type, entity LIMIT {MAX_FINDINGS}")

    known, external, background, most_important = organize(findings, counts)
    prompt = build_prompt(dt, counts, known, external, background, most_important)
    required = sorted({f["entity"] for f in external if f["severity"] in ("high", "medium")})

    # First attempt
    messages = [{"role": "user", "content": [{"text": prompt}]}]
    report, usage1 = converse(messages)
    issues = validate(report, prompt, required)
    attempts = [{"issues": issues, "usage": usage1}]
    log(f"attempt 1 issues={issues}")

    # One correction attempt, telling the model exactly what to fix
    if issues:
        messages += [
            {"role": "assistant", "content": [{"text": report}]},
            {"role": "user", "content": [{"text":
                "Your report has these problems:\n- " + "\n- ".join(issues) +
                "\nRewrite the full report fixing ONLY these problems. Keep everything else."}]},
        ]
        report, usage2 = converse(messages)
        issues = validate(report, prompt, required)
        attempts.append({"issues": issues, "usage": usage2})
        log(f"attempt 2 issues={issues}")

    # Audit trail: report + exact model input + validation results
    s3.put_object(Bucket=REPORT_BUCKET, Key=f"{base_key}/report.md",
                  Body=report.encode("utf-8"), ContentType="text/markdown")
    s3.put_object(Bucket=REPORT_BUCKET, Key=f"{base_key}/model_input.json",
                  Body=json.dumps({"dt": dt, "model_id": MODEL_ID, "system": SYSTEM_PROMPT,
                                   "prompt": prompt, "attempts": attempts},
                                  indent=2).encode("utf-8"),
                  ContentType="application/json")

    check = ("Automated checks: passed." if not issues else
             "WARNING - automated checks still flag: " + "; ".join(issues) +
             ". Review against the findings before acting.")
    footer = (f"\n\n---\n{check}\nGenerated by Amazon Bedrock ({MODEL_ID}) from {total} findings "
              f"in {len(attempts)} attempt(s).\n"
              f"Report, model input and checks: s3://{REPORT_BUCKET}/{base_key}/")
    sns.publish(TopicArn=TOPIC_ARN, Subject=subject, Message=report + footer)

    return {"dt": dt, "findings": total, "attempts": len(attempts),
            "final_issues": issues, "report": f"s3://{REPORT_BUCKET}/{base_key}/report.md"}