"""
Glue ETL job: raw_to_curated

Extract   raw VPC Flow Logs (space-delimited text) via the crawler's
          Data Catalog table  flowlogs_db.raw_awslogs
Transform clean types, rename columns, drop non-OK records, enrich
          (timestamps, protocol names, private/public IPs, /24 subnet,
          SYN-only flag), re-partition by EVENT date
Load      Snappy Parquet in the curated bucket, partitioned by dt, and
          create/update the catalog table  flowlogs_db.flows_curated

Milestone 3: full reprocess on every run (output path is purged first,
so re-running never creates duplicates).
Milestone 4 will switch this to incremental loads with job bookmarks.

Job parameter required:
  --CURATED_PATH  s3://<curated-bucket>/flows/
"""
import sys

from awsglue.context import GlueContext
from awsglue.dynamicframe import DynamicFrame
from awsglue.job import Job
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from pyspark.sql import functions as F

# -----------------------------------------------------------------------------
# Setup
# -----------------------------------------------------------------------------
args = getResolvedOptions(sys.argv, ["JOB_NAME", "CURATED_PATH"])

DATABASE = "flowlogs_db"
SOURCE_TABLE = "raw_awslogs"
TARGET_TABLE = "flows_curated"
CURATED_PATH = args["CURATED_PATH"].rstrip("/") + "/"

sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
spark.conf.set("spark.sql.session.timeZone", "UTC")  # epoch -> timestamp in UTC

job = Job(glueContext)
job.init(args["JOB_NAME"], args)

# -----------------------------------------------------------------------------
# 1) EXTRACT: read through the Data Catalog (schema + partitions come from the
#    crawler; Glue reads the gzipped files in S3 for us)
# -----------------------------------------------------------------------------
raw_dyf = glueContext.create_dynamic_frame.from_catalog(
    database=DATABASE,
    table_name=SOURCE_TABLE,
    transformation_ctx="raw_source",  # needed for job bookmarks in milestone 4
)

# Numeric columns can contain "-" in NODATA/SKIPDATA records, which makes Glue
# see them as a "choice" of long-or-string. Resolve every one explicitly:
# "-" becomes null instead of breaking the job.
numeric_cols = [
    "version", "srcport", "dstport", "protocol", "packets",
    "bytes", "start", "end", "tcp-flags",
]
raw_dyf = raw_dyf.resolveChoice(
    specs=[(c, "cast:long") for c in numeric_cols] + [("account-id", "cast:string")]
)

df = raw_dyf.toDF()

# Hyphens are legal in the catalog but painful everywhere else -> underscores.
df = df.toDF(*[c.replace("-", "_") for c in df.columns])

# Defensive: drop any header line that slipped through as a data row.
df = df.filter(F.coalesce(F.col("action"), F.lit("")) != "action")

df.cache()
raw_count = df.count()

# -----------------------------------------------------------------------------
# 2) TRANSFORM
# -----------------------------------------------------------------------------
# Only OK records describe real traffic. NODATA = no traffic in the window,
# SKIPDATA = AWS dropped records (capacity/error). Milestone 4 quarantines these
# instead of just dropping them.
ok = df.filter(F.col("log_status") == "OK")

PRIVATE_IP_RE = r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)"  # RFC 1918
IPV4_RE = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"

src_private = F.col("srcaddr").rlike(PRIVATE_IP_RE)
dst_private = F.col("dstaddr").rlike(PRIVATE_IP_RE)

curated = (
    ok
    # Account IDs are 12-character identifiers, not numbers (keep leading zeros)
    .withColumn("account_id", F.lpad(F.col("account_id"), 12, "0"))
    # Epoch seconds -> real timestamps
    .withColumn("start_time", F.col("start").cast("timestamp"))
    .withColumn("end_time", F.col("end").cast("timestamp"))
    .withColumn("duration_sec", (F.col("end") - F.col("start")).cast("int"))
    # Smaller, correct types
    .withColumn("srcport", F.col("srcport").cast("int"))
    .withColumn("dstport", F.col("dstport").cast("int"))
    .withColumn("protocol", F.col("protocol").cast("int"))
    .withColumn("tcp_flags", F.col("tcp_flags").cast("int"))
    # IANA protocol numbers -> names
    .withColumn(
        "protocol_name",
        F.when(F.col("protocol") == 6, "TCP")
        .when(F.col("protocol") == 17, "UDP")
        .when(F.col("protocol") == 1, "ICMP")
        .when(F.col("protocol") == 58, "ICMPv6")
        .otherwise("OTHER"),
    )
    # Network context
    .withColumn("src_is_private", src_private)
    .withColumn("dst_is_private", dst_private)
    .withColumn(
        "traffic_category",
        F.when(src_private & dst_private, "internal")
        .when(~src_private & dst_private, "inbound_external")
        .when(src_private & ~dst_private, "outbound_external")
        .otherwise("external"),
    )
    # /24 of the source: lets milestone 5 catch scans spread across many IPs
    .withColumn(
        "src_subnet_24",
        F.when(
            F.col("srcaddr").rlike(IPV4_RE),
            F.concat(F.regexp_extract("srcaddr", r"^(\d+\.\d+\.\d+)\.", 1), F.lit(".0/24")),
        ),
    )
    # TCP flags are OR'd over the window; exactly 2 = SYN with no handshake
    # completed (classic scan / refused-connection signature)
    .withColumn("is_syn_only", F.col("tcp_flags") == 2)
    # Partition by EVENT date (when traffic happened), not delivery hour
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

curated_count = curated.count()

# -----------------------------------------------------------------------------
# 3) LOAD: Parquet + catalog table in one step
# -----------------------------------------------------------------------------
# Full reprocess: clear previous output so reruns don't duplicate rows.
glueContext.purge_s3_path(CURATED_PATH, {"retentionPeriod": 0})

# One output file per day instead of many tiny files (small-file problem).
curated = curated.repartition("dt")

out_dyf = DynamicFrame.fromDF(curated, glueContext, "curated")

sink = glueContext.getSink(
    connection_type="s3",
    path=CURATED_PATH,
    enableUpdateCatalog=True,              # create/update flows_curated for us
    updateBehavior="UPDATE_IN_DATABASE",
    partitionKeys=["dt"],
    transformation_ctx="curated_sink",
)
sink.setFormat("glueparquet", compression="snappy")
sink.setCatalogInfo(catalogDatabase=DATABASE, catalogTableName=TARGET_TABLE)
sink.writeFrame(out_dyf)

print(
    f"[raw_to_curated] raw rows={raw_count} "
    f"non-OK dropped={raw_count - curated_count} "
    f"curated rows={curated_count}"
)

job.commit()