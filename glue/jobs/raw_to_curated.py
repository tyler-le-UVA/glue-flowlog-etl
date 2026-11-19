"""
Glue ETL job: raw_to_curated  (v2, milestone 4)

What changed from v1 (milestone 3):
  * INCREMENTAL: job bookmarks are ON. Each run reads only raw files it hasn't
    processed before, and APPENDS to the curated table (no more purge).
  * EMPTY-RUN GUARD: if there's nothing new, the job logs it and exits cleanly.
  * DATA QUALITY: every batch is evaluated with Glue Data Quality (DQDL rules).
      - rows that pass  -> curated table (flows_curated)
      - rows that fail  -> quarantine/dq_failed/   (JSON, with the failed rules)
      - non-OK records  -> quarantine/non_ok/      (NODATA/SKIPDATA, kept, not dropped)
  * CIRCUIT BREAKER: if more than MAX_FAIL_PCT of a batch fails, the job FAILS
    before writing anything. No commit -> the bookmark doesn't advance -> the
    same files are retried next run after you fix the problem.

Job parameters required:
  --CURATED_PATH     s3://<curated-bucket>/flows/
  --QUARANTINE_PATH  s3://<curated-bucket>/quarantine/
Job details:
  Job bookmark = Enable
"""
import sys

from awsglue.context import GlueContext
from awsglue.dynamicframe import DynamicFrame
from awsglue.job import Job
from awsglue.transforms import SelectFromCollection
from awsglue.utils import getResolvedOptions
from awsgluedq.transforms import EvaluateDataQuality
from pyspark.context import SparkContext
from pyspark.sql import functions as F

# -----------------------------------------------------------------------------
# Setup
# -----------------------------------------------------------------------------
args = getResolvedOptions(sys.argv, ["JOB_NAME", "CURATED_PATH", "QUARANTINE_PATH"])

DATABASE = "flowlogs_db"
SOURCE_TABLE = "raw_awslogs"
TARGET_TABLE = "flows_curated"
CURATED_PATH = args["CURATED_PATH"].rstrip("/") + "/"
QUARANTINE_PATH = args["QUARANTINE_PATH"].rstrip("/") + "/"
MAX_FAIL_PCT = 5.0  # circuit breaker threshold

# Data Quality rules (DQDL). Row-level rules decide pass/fail per row;
# RowCount is a dataset-level rule (reported, not applied to individual rows).
RULESET = """
Rules = [
    IsComplete "srcaddr",
    IsComplete "dstaddr",
    IsComplete "start_time",
    IsComplete "dt",
    ColumnValues "action" in ["ACCEPT", "REJECT"],
    ColumnValues "protocol_name" in ["TCP", "UDP", "ICMP", "ICMPv6", "OTHER"],
    ColumnValues "srcport" between -1 and 65536,
    ColumnValues "dstport" between -1 and 65536,
    ColumnValues "duration_sec" >= 0,
    ColumnLength "account_id" = 12,
    RowCount > 0
]
"""

DQ_COLS = [
    "DataQualityRulesPass", "DataQualityRulesFail",
    "DataQualityRulesSkip", "DataQualityEvaluationResult",
]

sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
spark.conf.set("spark.sql.session.timeZone", "UTC")

job = Job(glueContext)
job.init(args["JOB_NAME"], args)

PRIVATE_IP_RE = r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)"
IPV4_RE = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"


def log(msg):
    print(f"[raw_to_curated] {msg}")


def run_pipeline(raw_dyf):
    # -------------------------------------------------------------------------
    # 1) Clean up the raw frame (same as v1)
    # -------------------------------------------------------------------------
    numeric_cols = [
        "version", "srcport", "dstport", "protocol", "packets",
        "bytes", "start", "end", "tcp-flags",
    ]
    raw_dyf = raw_dyf.resolveChoice(
        specs=[(c, "cast:long") for c in numeric_cols] + [("account-id", "cast:string")]
    )
    df = raw_dyf.toDF()
    df = df.toDF(*[c.replace("-", "_") for c in df.columns])
    df = df.filter(F.coalesce(F.col("action"), F.lit("")) != "action")
    df.cache()
    raw_count = df.count()

    # -------------------------------------------------------------------------
    # 2) Split: OK records continue; everything else is quarantined (kept!)
    # -------------------------------------------------------------------------
    is_ok = F.coalesce(F.col("log_status"), F.lit("")) == "OK"
    ok = df.filter(is_ok)
    non_ok = df.filter(~is_ok)
    non_ok_count = non_ok.count()  # written in step 6, after the circuit breaker

    # -------------------------------------------------------------------------
    # 3) Transform + enrich (same as v1)
    # -------------------------------------------------------------------------
    src_private = F.col("srcaddr").rlike(PRIVATE_IP_RE)
    dst_private = F.col("dstaddr").rlike(PRIVATE_IP_RE)

    curated = (
        ok
        .withColumn("account_id", F.lpad(F.col("account_id"), 12, "0"))
        .withColumn("start_time", F.col("start").cast("timestamp"))
        .withColumn("end_time", F.col("end").cast("timestamp"))
        .withColumn("duration_sec", (F.col("end") - F.col("start")).cast("int"))
        .withColumn("srcport", F.col("srcport").cast("int"))
        .withColumn("dstport", F.col("dstport").cast("int"))
        .withColumn("protocol", F.col("protocol").cast("int"))
        .withColumn("tcp_flags", F.col("tcp_flags").cast("int"))
        .withColumn(
            "protocol_name",
            F.when(F.col("protocol") == 6, "TCP")
            .when(F.col("protocol") == 17, "UDP")
            .when(F.col("protocol") == 1, "ICMP")
            .when(F.col("protocol") == 58, "ICMPv6")
            .otherwise("OTHER"),
        )
        .withColumn("src_is_private", src_private)
        .withColumn("dst_is_private", dst_private)
        .withColumn(
            "traffic_category",
            F.when(src_private & dst_private, "internal")
            .when(~src_private & dst_private, "inbound_external")
            .when(src_private & ~dst_private, "outbound_external")
            .otherwise("external"),
        )
        .withColumn(
            "src_subnet_24",
            F.when(
                F.col("srcaddr").rlike(IPV4_RE),
                F.concat(F.regexp_extract("srcaddr", r"^(\d+\.\d+\.\d+)\.", 1), F.lit(".0/24")),
            ),
        )
        .withColumn("is_syn_only", F.col("tcp_flags") == 2)
        .withColumn("dt", F.date_format("start_time", "yyyy-MM-dd"))
        .select(
            "account_id", "vpc_id", "subnet_id", "instance_id", "interface_id",
            "srcaddr", "dstaddr", "srcport", "dstport",
            "protocol", "protocol_name", "packets", "bytes",
            "start_time", "end_time", "duration_sec",
            "action", "flow_direction", "tcp_flags", "is_syn_only",
            "pkt_srcaddr", "pkt_dstaddr",
            "src_is_private", "dst_is_private", "traffic_category", "src_subnet_24",
            "dt",
        )
    )

    # -------------------------------------------------------------------------
    # 4) DATA QUALITY: evaluate every row against the ruleset
    # -------------------------------------------------------------------------
    curated_dyf = DynamicFrame.fromDF(curated, glueContext, "curated_pre_dq")

    dq_results = EvaluateDataQuality().process_rows(
        frame=curated_dyf,
        ruleset=RULESET,
        publishing_options={
            "dataQualityEvaluationContext": "flowlogs_curated_dq",
            "enableDataQualityCloudWatchMetrics": True,
            "enableDataQualityResultsPublishing": True,
        },
        additional_options={"performanceTuning.caching": "CACHE_NOTHING"},
    )

    # Dataset-level summary: one row per rule, Passed/Failed. Printed to the log.
    rule_outcomes = SelectFromCollection.apply(dfc=dq_results, key="ruleOutcomes").toDF()
    rule_outcomes.select("Rule", "Outcome", "FailureReason").show(truncate=False)

    # Row-level results: original columns + DataQuality* columns
    rows = SelectFromCollection.apply(dfc=dq_results, key="rowLevelOutcomes").toDF()
    rows.cache()
    passed = rows.filter(F.col("DataQualityEvaluationResult") == "Passed").drop(*DQ_COLS)
    failed = rows.filter(F.col("DataQualityEvaluationResult") != "Passed")
    passed_count = passed.count()
    failed_count = failed.count()
    checked = passed_count + failed_count
    fail_pct = (100.0 * failed_count / checked) if checked else 0.0

    log(
        f"raw rows={raw_count} non_ok_quarantined={non_ok_count} "
        f"dq_passed={passed_count} dq_failed={failed_count} fail_pct={fail_pct:.2f}"
    )

    # -------------------------------------------------------------------------
    # 5) CIRCUIT BREAKER: too many bad rows means something upstream is broken.
    #    Fail BEFORE writing; no job.commit() -> bookmark doesn't advance.
    # -------------------------------------------------------------------------
    if fail_pct > MAX_FAIL_PCT:
        raise RuntimeError(
            f"Data quality circuit breaker: {fail_pct:.2f}% of rows failed "
            f"(limit {MAX_FAIL_PCT}%). Nothing written; batch will be retried."
        )

    # -------------------------------------------------------------------------
    # 6) LOAD: quarantine non-OK + failed rows, append passed rows to curated.
    #    Nothing is written until the circuit breaker has passed.
    # -------------------------------------------------------------------------
    if non_ok_count > 0:
        (non_ok
            .withColumn("quarantine_reason", F.lit("log_status is not OK"))
            .withColumn("quarantined_at", F.current_timestamp())
            .write.mode("append").json(QUARANTINE_PATH + "non_ok/"))

    if failed_count > 0:
        (failed
            .withColumn("quarantine_reason", F.concat_ws("; ", F.col("DataQualityRulesFail")))
            .withColumn("quarantined_at", F.current_timestamp())
            .drop(*DQ_COLS)
            .write.mode("append").json(QUARANTINE_PATH + "dq_failed/"))

    if passed_count > 0:
        out_dyf = DynamicFrame.fromDF(passed.repartition("dt"), glueContext, "curated")
        sink = glueContext.getSink(
            connection_type="s3",
            path=CURATED_PATH,
            enableUpdateCatalog=True,
            updateBehavior="UPDATE_IN_DATABASE",
            partitionKeys=["dt"],
            transformation_ctx="curated_sink",
        )
        sink.setFormat("glueparquet", compression="snappy")
        sink.setCatalogInfo(catalogDatabase=DATABASE, catalogTableName=TARGET_TABLE)
        sink.writeFrame(out_dyf)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
# With bookmarks enabled, this returns ONLY files not processed by a previous
# successful run (tracked under the name "raw_source").
raw_dyf = glueContext.create_dynamic_frame.from_catalog(
    database=DATABASE,
    table_name=SOURCE_TABLE,
    transformation_ctx="raw_source",
)

if raw_dyf.count() == 0:
    log("no new raw data since the last successful run; nothing to do")
else:
    run_pipeline(raw_dyf)

job.commit()  # saves the bookmark: only reached if everything above succeeded