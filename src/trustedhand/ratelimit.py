"""Fixed-window rate limiter on DynamoDB. One atomic UpdateItem per check."""
from botocore.exceptions import ClientError

from . import db


def hit(key, limit, window_s):
    """Count one hit on `key`. True if still within `limit` for the current window."""
    t = db.now()
    bucket = t // window_s
    try:
        db.tbl("ratelimit").update_item(
            Key={"key": f"{key}#{window_s}#{bucket}"},
            UpdateExpression="ADD #c :one SET #t = if_not_exists(#t, :ttl)",
            ConditionExpression="attribute_not_exists(#c) OR #c < :limit",
            ExpressionAttributeNames={"#c": "count", "#t": "ttl"},
            ExpressionAttributeValues={":one": 1, ":limit": limit, ":ttl": (bucket + 1) * window_s + 60},
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise
