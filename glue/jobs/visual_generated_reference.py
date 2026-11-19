import sys
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
from awsgluedq.transforms import EvaluateDataQuality
from awsglue import DynamicFrame
import gs_derived
import re

def sparkSqlQuery(glueContext, query, mapping, transformation_ctx) -> DynamicFrame:
    for alias, frame in mapping.items():
        frame.toDF().createOrReplaceTempView(alias)
    result = spark.sql(query)
    return DynamicFrame.fromDF(result, glueContext, transformation_ctx)
args = getResolvedOptions(sys.argv, ['JOB_NAME'])
sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args['JOB_NAME'], args)

# Default ruleset used by all target nodes with data quality enabled
DEFAULT_DATA_QUALITY_RULESET = """
    Rules = [
        ColumnCount > 0
    ]
"""

# Script generated for node AWS Glue Data Catalog
AWSGlueDataCatalog_node1795035006362 = glueContext.create_dynamic_frame.from_catalog(database="flowlogs_db", table_name="raw_awslogs", transformation_ctx="AWSGlueDataCatalog_node1795035006362")

# Script generated for node Change Schema
ChangeSchema_node1795035029012 = ApplyMapping.apply(frame=AWSGlueDataCatalog_node1795035006362, mappings=[("account-id", "long", "account_id", "string"), ("interface-id", "string", "interface_id", "string"), ("srcaddr", "string", "srcaddr", "string"), ("dstaddr", "string", "dstaddr", "string"), ("srcport", "long", "srcport", "int"), ("dstport", "long", "dstport", "int"), ("protocol", "long", "protocol", "int"), ("packets", "long", "packets", "long"), ("bytes", "long", "bytes", "long"), ("start", "long", "start", "long"), ("end", "long", "end", "long"), ("action", "string", "action", "string"), ("log-status", "string", "log_status", "string"), ("vpc-id", "string", "vpc_id", "string"), ("subnet-id", "string", "subnet_id", "string"), ("instance-id", "string", "instance_id", "string"), ("tcp-flags", "long", "tcp_flags", "int"), ("flow-direction", "string", "flow_direction", "string"), ("pkt-srcaddr", "string", "pkt_srcaddr", "string"), ("pkt-dstaddr", "string", "pkt_dstaddr", "string")], transformation_ctx="ChangeSchema_node1795035029012")

# Script generated for node Filter
Filter_node1795035948586 = Filter.apply(frame=ChangeSchema_node1795035029012, f=lambda row: (bool(re.match("^OK$", row["log_status"]))), transformation_ctx="Filter_node1795035948586")

# Script generated for node Derived Column
DerivedColumn_node1795035995185 = Filter_node1795035948586.gs_derived(colName="start_time", expr="CAST(start AS timestamp)")

# Script generated for node SQL Query
SqlQuery0 = '''
WITH e AS (
  SELECT *,
    CAST(`end` AS timestamp)                AS end_time,
    CAST(`end` - start AS int)              AS duration_sec,
    CASE protocol WHEN 6 THEN 'TCP' WHEN 17 THEN 'UDP'
                  WHEN 1 THEN 'ICMP' WHEN 58 THEN 'ICMPv6'
                  ELSE 'OTHER' END          AS protocol_name,
    (srcaddr LIKE '10.%' OR srcaddr LIKE '192.168.%' OR
     (srcaddr LIKE '172.%' AND CAST(split(srcaddr, '[.]')[1] AS INT) BETWEEN 16 AND 31))
                                            AS src_is_private,
    (dstaddr LIKE '10.%' OR dstaddr LIKE '192.168.%' OR
     (dstaddr LIKE '172.%' AND CAST(split(dstaddr, '[.]')[1] AS INT) BETWEEN 16 AND 31))
                                            AS dst_is_private,
    concat(substring_index(srcaddr, '.', 3), '.0/24') AS src_subnet_24,
    tcp_flags = 2                           AS is_syn_only,
    date_format(start_time, 'yyyy-MM-dd')   AS dt
  FROM myDataSource
)
SELECT *,
  CASE WHEN src_is_private AND dst_is_private     THEN 'internal'
       WHEN NOT src_is_private AND dst_is_private THEN 'inbound_external'
       WHEN src_is_private AND NOT dst_is_private THEN 'outbound_external'
       ELSE 'external' END AS traffic_category
FROM e
'''
SQLQuery_node1795036054735 = sparkSqlQuery(glueContext, query = SqlQuery0, mapping = {"myDataSource":DerivedColumn_node1795035995185}, transformation_ctx = "SQLQuery_node1795036054735")

# Script generated for node Drop Fields
DropFields_node1795036439054 = DropFields.apply(frame=SQLQuery_node1795036054735, paths=["start", "end", "log_status"], transformation_ctx="DropFields_node1795036439054")

# Script generated for node Amazon S3
EvaluateDataQuality().process_rows(frame=DropFields_node1795036439054, ruleset=DEFAULT_DATA_QUALITY_RULESET, publishing_options={"dataQualityEvaluationContext": "EvaluateDataQuality_node1795032154754", "enableDataQualityResultsPublishing": True}, additional_options={"dataQualityResultsPublishing.strategy": "BEST_EFFORT", "observations.scope": "ALL"})
AmazonS3_node1795036458948 = glueContext.getSink(path="s3://glue-flowlog-etl-curated-209901331329-us-east-1/flows_visual/", connection_type="s3", updateBehavior="UPDATE_IN_DATABASE", partitionKeys=["dt"], enableUpdateCatalog=True, transformation_ctx="AmazonS3_node1795036458948")
AmazonS3_node1795036458948.setCatalogInfo(catalogDatabase="flowlogs_db",catalogTableName="flows_curated_visual")
AmazonS3_node1795036458948.setFormat("glueparquet", compression="snappy")
AmazonS3_node1795036458948.writeFrame(DropFields_node1795036439054)
job.commit()