"""
Glue ETL job: curated_to_findings  (milestone 5)

Reads   flowlogs_db.flows_curated  (clean, enriched flow records)
Detects five kinds of suspicious activity (thresholds chosen from the
        milestone 5 notebook exploration, all tunable below)
Writes  flowlogs_db.findings  (Parquet, partitioned by dt): one row per finding

Design choice: FULL RECOMPUTE on every run (output purged first).
  Detections need whole-day windows and 24-hour baselines, so incremental
  bookmarks don't fit naturally. The data is small, so recomputing is cheap
  and makes reruns safe. At larger scale you'd recompute only the last N days
  and overwrite just those dt partitions.

Job parameter required:
  --FINDINGS_PATH  s3://<curated-bucket>/findings/
Job details:
  Job bookmark = Disable
"""
import sys

from awsglue.context import GlueContext
from awsglue.dynamicframe import DynamicFrame
from awsglue.job import Job
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from pyspark.sql import Window
from pyspark.sql import functions as F

# -----------------------------------------------------------------------------
# Setup
# -----------------------------------------------------------------------------
args = getResolvedOptions(sys.argv, ["JOB_NAME", "FINDINGS_PATH"])

DATABASE = "flowlogs_db"
SOURCE_TABLE = "flows_curated"
TARGET_TABLE = "findings"
FINDINGS_PATH = args["FINDINGS_PATH"].rstrip("/") + "/"

# -----------------------------------------------------------------------------
# Thresholds (from the notebook exploration)
# -----------------------------------------------------------------------------
VERTICAL_MIN_PORTS = 100        # distinct ports per source per day
VERTICAL_MEDIUM_PORTS = 300
VERTICAL_HIGH_PORTS = 1000

DIST_MIN_SOURCE_IPS = 5         # per /24 per day
DIST_MIN_PORTS_PER_IP = 10
DIST_MIN_PORTS = 200
DIST_HIGH_PORTS = 1000

INFRA_MIN_SOURCE_IPS = 50       # per /24 per day
INFRA_MAX_PORTS_PER_IP = 3

SPIKE_MIN_Z = 3.0               # standard deviations above the baseline
SPIKE_HIGH_Z = 6.0
SPIKE_MIN_REJECTS = 50          # ignore tiny absolute numbers
SPIKE_BASELINE_HOURS = 24       # baseline = previous 24 hours for that host
SPIKE_MIN_BASELINE_HOURS = 6    # don't trust a baseline built on < 6 hours

COMMON_OUTBOUND_PORTS = [80, 123, 443]  # HTTP, NTP, HTTPS

FINDING_COLS = [
    "finding_id", "finding_type", "severity", "entity", "entity_type", "target",
    "window_start", "window_end", "metrics", "description", "detected_at", "dt",
]

sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
spark.conf.set("spark.sql.session.timeZone", "UTC")

job = Job(glueContext)
job.init(args["JOB_NAME"], args)


def log(msg):
    print(f"[curated_to_findings] {msg}")


def finalize(df, finding_type, severity, entity, entity_type, target,
             window_start, window_end, metrics, description):
    """Shape any detection's rows into the common findings schema."""
    out = df.select(
        F.lit(finding_type).alias("finding_type"),
        severity.alias("severity"),
        entity.cast("string").alias("entity"),
        entity_type.alias("entity_type"),
        target.cast("string").alias("target"),
        window_start.alias("window_start"),
        window_end.alias("window_end"),
        F.to_json(F.struct(*metrics)).alias("metrics"),   # the numbers behind it
        description.alias("description"),                # human-readable sentence
        F.date_format(window_start, "yyyy-MM-dd").alias("dt"),
    )
    # Deterministic ID: the same finding gets the same ID on every rerun
    return (out
        .withColumn("finding_id", F.substring(F.sha2(F.concat_ws(
            "|", "finding_type", "entity", "target", F.col("window_start").cast("string")), 256), 1, 16))
        .withColumn("detected_at", F.current_timestamp()))


# -----------------------------------------------------------------------------
# Load
# -----------------------------------------------------------------------------
flows = glueContext.create_dynamic_frame.from_catalog(
    database=DATABASE, table_name=SOURCE_TABLE
).toDF()
flows = flows.withColumn("hour_window", F.date_trunc("hour", "start_time"))
flows.cache()
rejects = flows.filter(F.col("action") == "REJECT")
log(f"flows loaded={flows.count()}")

# -----------------------------------------------------------------------------
# 1) Vertical port scan: one source, many ports, in one day
# -----------------------------------------------------------------------------
v = (rejects
    .groupBy("srcaddr", "dt")
    .agg(F.countDistinct("dstport").alias("distinct_ports"),
         F.count("*").alias("rejected_flows"),
         F.countDistinct("dstaddr").alias("targets_hit"),
         F.concat_ws(",", F.sort_array(F.collect_set("dstaddr"))).alias("targets"),
         F.min("start_time").alias("first_seen"),
         F.max("end_time").alias("last_seen"),
         F.first("src_is_private").alias("src_is_private"))
    .filter(F.col("distinct_ports") >= VERTICAL_MIN_PORTS))
    
v = v.withColumn("src_subnet_24", F.concat(F.regexp_extract("srcaddr", r"^(\d+\.\d+\.\d+)\.", 1), F.lit(".0/24")))

vertical = finalize(
    v, "vertical_port_scan",
    severity=(F.when(F.col("src_is_private"), "high")      # internal scanning = possible lateral movement
              .when(F.col("distinct_ports") >= VERTICAL_HIGH_PORTS, "high")
              .when(F.col("distinct_ports") >= VERTICAL_MEDIUM_PORTS, "medium")
              .otherwise("low")),
    entity=F.col("srcaddr"),
    entity_type=F.when(F.col("src_is_private"), "internal_ip").otherwise("external_ip"),
    target=F.col("targets"),
    window_start=F.col("first_seen"),
    window_end=F.col("last_seen"),
    metrics=["distinct_ports", "rejected_flows", "targets_hit"],
    description=F.format_string(
        "%s source %s probed %d distinct ports on %s (%d rejected flows) on %s.",
        F.when(F.col("src_is_private"), "Internal").otherwise("External"),
        F.col("srcaddr"), F.col("distinct_ports"), F.col("targets"),
        F.col("rejected_flows"), F.col("dt")),
)

# -----------------------------------------------------------------------------
# 2 + 3) Group inbound rejects by source /24 (shared by both detections)
# -----------------------------------------------------------------------------
s = (rejects
    .filter(F.col("traffic_category") == "inbound_external")
    .groupBy("src_subnet_24", "dt")
    .agg(F.countDistinct("srcaddr").alias("source_ips"),
         F.countDistinct("dstport").alias("ports_probed"),
         F.count("*").alias("rejected_flows"),
         F.concat_ws(",", F.sort_array(F.collect_set("dstaddr"))).alias("targets"),
         F.min("start_time").alias("first_seen"),
         F.max("end_time").alias("last_seen"))
    .withColumn("ports_per_ip", F.round(F.col("ports_probed") / F.col("source_ips"), 1)))
s.cache()

# 2) Distributed scan: a few hosts, each covering a big slice of the port list
d = s.filter((F.col("source_ips") >= DIST_MIN_SOURCE_IPS)
             & (F.col("ports_per_ip") >= DIST_MIN_PORTS_PER_IP)
             & (F.col("ports_probed") >= DIST_MIN_PORTS))

distributed = finalize(
    d, "distributed_scan",
    severity=F.when(F.col("ports_probed") >= DIST_HIGH_PORTS, "high").otherwise("medium"),
    entity=F.col("src_subnet_24"),
    entity_type=F.lit("subnet_24"),
    target=F.col("targets"),
    window_start=F.col("first_seen"),
    window_end=F.col("last_seen"),
    metrics=["source_ips", "ports_probed", "ports_per_ip", "rejected_flows"],
    description=F.format_string(
        "%d hosts in %s together probed %d distinct ports on %s (%.1f ports per host) on %s.",
        F.col("source_ips"), F.col("src_subnet_24"), F.col("ports_probed"),
        F.col("targets"), F.col("ports_per_ip"), F.col("dt")),
)

flagged = d.select("src_subnet_24", "dt").withColumn("in_campaign", F.lit(True))
keep = (v.join(flagged, ["src_subnet_24", "dt"], "left")
         .filter(F.col("in_campaign").isNull()
                 | F.col("src_is_private")
                 | (F.col("distinct_ports") >= VERTICAL_HIGH_PORTS))
         .select("srcaddr", "dt"))
vertical = vertical.join(keep.withColumnRenamed("srcaddr", "entity"), ["entity", "dt"], "inner")

# 3) Scanning infrastructure: many hosts, each touching only a port or two
i = s.filter((F.col("source_ips") >= INFRA_MIN_SOURCE_IPS)
             & (F.col("ports_per_ip") < INFRA_MAX_PORTS_PER_IP))

infrastructure = finalize(
    i, "scanning_infrastructure",
    severity=F.lit("info"),
    entity=F.col("src_subnet_24"),
    entity_type=F.lit("subnet_24"),
    target=F.col("targets"),
    window_start=F.col("first_seen"),
    window_end=F.col("last_seen"),
    metrics=["source_ips", "ports_probed", "ports_per_ip", "rejected_flows"],
    description=F.format_string(
        "Mass-scanning infrastructure: %d hosts in %s touched %d ports on %s (about %.1f ports per host) on %s.",
        F.col("source_ips"), F.col("src_subnet_24"), F.col("ports_probed"),
        F.col("targets"), F.col("ports_per_ip"), F.col("dt")),
)

# -----------------------------------------------------------------------------
# 4) REJECT spike: an hour far above that host's own recent baseline
# -----------------------------------------------------------------------------
hourly = (rejects
    .groupBy("dstaddr", "hour_window")
    .agg(F.count("*").alias("rejects")))

w = (Window.partitionBy("dstaddr").orderBy("hour_window")
     .rowsBetween(-SPIKE_BASELINE_HOURS, -1))

sp = (hourly
    .withColumn("baseline_avg", F.avg("rejects").over(w))
    .withColumn("baseline_std", F.stddev("rejects").over(w))
    .withColumn("baseline_hours", F.count("rejects").over(w))
    .withColumn("z_score", (F.col("rejects") - F.col("baseline_avg")) / F.col("baseline_std"))
    .filter((F.col("z_score") >= SPIKE_MIN_Z)
            & (F.col("rejects") >= SPIKE_MIN_REJECTS)
            & (F.col("baseline_hours") >= SPIKE_MIN_BASELINE_HOURS)))

# Who caused it? Top single source AND top /24, each with its share of the hour
def top_by(col, prefix):
    g = (rejects.groupBy("dstaddr", "hour_window", col)
         .agg(F.count("*").alias(f"{prefix}_flows")))
    r = Window.partitionBy("dstaddr", "hour_window").orderBy(F.desc(f"{prefix}_flows"))
    return (g.withColumn("rk", F.row_number().over(r)).filter(F.col("rk") == 1)
             .select("dstaddr", "hour_window", F.col(col).alias(prefix), f"{prefix}_flows"))

sp = (sp.join(top_by("srcaddr", "top_source"), ["dstaddr", "hour_window"], "left")
        .join(top_by("src_subnet_24", "top_subnet"), ["dstaddr", "hour_window"], "left")
        .withColumn("top_source_pct", F.round(100 * F.col("top_source_flows") / F.col("rejects"), 1))
        .withColumn("top_subnet_pct", F.round(100 * F.col("top_subnet_flows") / F.col("rejects"), 1))
        .withColumn("baseline_avg", F.round("baseline_avg", 1))
        .withColumn("z_score", F.round("z_score", 2))
        .withColumn("times_normal", F.round(F.col("rejects") / F.col("baseline_avg"), 1)))

spikes = finalize(
    sp, "reject_spike",
    severity=F.when(F.col("z_score") >= SPIKE_HIGH_Z, "high").otherwise("medium"),
    entity=F.col("top_subnet"),
    entity_type=F.lit("subnet_24"),
    target=F.col("dstaddr"),
    window_start=F.col("hour_window"),
    window_end=F.col("hour_window") + F.expr("INTERVAL 1 HOUR"),
    metrics=["rejects", "baseline_avg", "z_score", "times_normal",
             "top_source", "top_source_flows", "top_source_pct",
             "top_subnet", "top_subnet_flows", "top_subnet_pct"],
    description=F.format_string(
        "%s received %d rejected connections in the hour starting %s UTC, %.1fx its normal %.0f per hour (z=%.1f). Top /24: %s (%.1f%% of the hour). Top single source: %s (%.1f%%).",
        F.col("dstaddr"), F.col("rejects"),
        F.date_format("hour_window", "yyyy-MM-dd HH:mm"),
        F.col("times_normal"), F.col("baseline_avg"), F.col("z_score"),
        F.col("top_subnet"), F.col("top_subnet_pct"),
        F.col("top_source"), F.col("top_source_pct")),
)

# -----------------------------------------------------------------------------
# 5) New external destination on an uncommon port
# -----------------------------------------------------------------------------
nd = (flows
    .filter((F.col("traffic_category") == "outbound_external")
            & (~F.col("dstport").isin(COMMON_OUTBOUND_PORTS)))
    .groupBy("srcaddr", "dstaddr", "dstport")
    .agg(F.min("start_time").alias("first_seen"),
         F.max("end_time").alias("last_seen"),
         F.count("*").alias("flows"),
         F.sum("bytes").alias("bytes_total"),
         F.first("protocol_name").alias("protocol_name")))

new_destinations = finalize(
    nd, "new_external_destination",
    severity=F.lit("medium"),
    entity=F.col("srcaddr"),
    entity_type=F.lit("internal_ip"),
    target=F.concat_ws(":", F.col("dstaddr"), F.col("dstport").cast("string")),
    window_start=F.col("first_seen"),
    window_end=F.col("last_seen"),
    metrics=["flows", "bytes_total", "protocol_name"],
    description=F.format_string(
        "%s contacted new external destination %s on uncommon %s port %d (%d flows, %d bytes), first seen %s UTC.",
        F.col("srcaddr"), F.col("dstaddr"), F.col("protocol_name"), F.col("dstport"),
        F.col("flows"), F.col("bytes_total"),
        F.date_format("first_seen", "yyyy-MM-dd HH:mm")),
)

# -----------------------------------------------------------------------------
# Combine + write
# -----------------------------------------------------------------------------
findings = (vertical
    .unionByName(distributed)
    .unionByName(infrastructure)
    .unionByName(spikes)
    .unionByName(new_destinations)
    .select(*FINDING_COLS))
findings.cache()

total = findings.count()
log(f"findings total={total}")
findings.groupBy("finding_type", "severity").count().orderBy("finding_type", "severity").show(truncate=False)

# Full recompute: clear previous output so reruns never duplicate findings
glueContext.purge_s3_path(FINDINGS_PATH, {"retentionPeriod": 0})

if total > 0:
    out_dyf = DynamicFrame.fromDF(findings.repartition("dt"), glueContext, "findings")
    sink = glueContext.getSink(
        connection_type="s3",
        path=FINDINGS_PATH,
        enableUpdateCatalog=True,
        updateBehavior="UPDATE_IN_DATABASE",
        partitionKeys=["dt"],
        transformation_ctx="findings_sink",
    )
    sink.setFormat("glueparquet", compression="snappy")
    sink.setCatalogInfo(catalogDatabase=DATABASE, catalogTableName=TARGET_TABLE)
    sink.writeFrame(out_dyf)

job.commit()