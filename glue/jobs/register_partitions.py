"""
Glue Python shell job: register_partitions  (milestone 6)

Replaces the crawler in the workflow. Registers new partitions of
flowlogs_db.raw_awslogs using ONLY the S3 folder names
(aws-account-id=/aws-service=/aws-region=/year=/month=/day=/hour=).

Why not a crawler? A crawler samples file CONTENTS to decide how folders
group into tables. One malformed file made it (a) split a day into
per-hour tables and (b) later skip the whole day, silently hiding real
data. This job never opens a file, so bad content can't change the
catalog. Bad content is the ETL job's problem (Data Quality + quarantine).

Every new partition gets the TABLE's schema/format, so the schema is owned
by us, not inferred.

Job type: Python shell (Python 3.9), 1/16 DPU. No job parameters needed.
"""
import copy

import boto3

DATABASE = "flowlogs_db"
TABLE = "raw_awslogs"

glue = boto3.client("glue")
s3 = boto3.client("s3")


def log(msg):
    print(f"[register_partitions] {msg}")


# --- 1. Read the table: partition keys, location, storage format ------------
table = glue.get_table(DatabaseName=DATABASE, Name=TABLE)["Table"]
keys = [k["Name"] for k in table["PartitionKeys"]]
location = table["StorageDescriptor"]["Location"].rstrip("/") + "/"
bucket, prefix = location.replace("s3://", "", 1).split("/", 1)
log(f"table location={location} partition keys={keys}")

# --- 2. Partitions already in the catalog ------------------------------------
existing = set()
for page in glue.get_paginator("get_partitions").paginate(DatabaseName=DATABASE, TableName=TABLE):
    for p in page["Partitions"]:
        existing.add(tuple(p["Values"]))
log(f"existing partitions={len(existing)}")

# --- 3. Partition folders that exist in S3 (from object keys only) -----------
found = {}
for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
    for obj in page.get("Contents", []):
        parts = obj["Key"][len(prefix):].split("/")[:-1]  # folder segments only
        if len(parts) != len(keys):
            continue
        if not all(seg.startswith(f"{k}=") for seg, k in zip(parts, keys)):
            continue
        values = tuple(seg.split("=", 1)[1] for seg in parts)
        found[values] = f"s3://{bucket}/{prefix}{'/'.join(parts)}/"
log(f"partition folders in S3={len(found)}")

# --- 4. Register the missing ones with the TABLE's schema --------------------
missing = [v for v in found if v not in existing]
log(f"new partitions to register={len(missing)}")

created, errors = 0, []
for i in range(0, len(missing), 100):  # API limit: 100 per call
    batch = []
    for values in missing[i:i + 100]:
        sd = copy.deepcopy(table["StorageDescriptor"])
        sd["Location"] = found[values]
        batch.append({
            "Values": list(values),
            "StorageDescriptor": sd,
            "Parameters": dict(table.get("Parameters", {})),
        })
    resp = glue.batch_create_partition(
        DatabaseName=DATABASE, TableName=TABLE, PartitionInputList=batch)
    errors.extend(resp.get("Errors", []))
    created += len(batch) - len(resp.get("Errors", []))
    for values in missing[i:i + 100]:
        log(f"  + {'/'.join(values)}")

log(f"registered={created} errors={len(errors)}")
for e in errors:
    log(f"  ERROR {e}")
if errors:
    raise RuntimeError(f"{len(errors)} partitions failed to register")