"""Table definitions for moto tests. Must match infra/dynamodb.tf and docs/DESIGN.md."""
TABLES = {
    "households": [("household_id", "HASH")],
    "sessions": [("pk", "HASH")],
    "payees": [("household_id", "HASH"), ("payee_id", "RANGE")],
    "bills": [("household_id", "HASH"), ("bill_id", "RANGE")],
    "ledger": [("household_id", "HASH"), ("sk", "RANGE")],
    "requests": [("household_id", "HASH"), ("request_id", "RANGE")],
    "approvals": [("request_id", "HASH")],
    "inbox": [("household_id", "HASH"), ("sk", "RANGE")],
    "receipts": [("household_id", "HASH"), ("sk", "RANGE")],
    "ratelimit": [("key", "HASH")],
    "strikes": [("session_id", "HASH")],
}


def create_all(ddb, prefix="th-"):
    for name, keys in TABLES.items():
        ddb.create_table(
            TableName=prefix + name,
            KeySchema=[{"AttributeName": k, "KeyType": t} for k, t in keys],
            AttributeDefinitions=[{"AttributeName": k, "AttributeType": "S"} for k, _ in keys],
            BillingMode="PAY_PER_REQUEST",
        )
