# On-demand tables, TTL on `ttl`, no point-in-time recovery (demo data).
# Must match docs/DESIGN.md and tests/tables.py.

locals {
  tables = {
    households = { hash = "household_id" }
    sessions   = { hash = "pk" }
    payees     = { hash = "household_id", range = "payee_id" }
    bills      = { hash = "household_id", range = "bill_id" }
    ledger     = { hash = "household_id", range = "sk" }
    requests   = { hash = "household_id", range = "request_id", stream = true }
    approvals  = { hash = "request_id" }
    inbox      = { hash = "household_id", range = "sk" }
    receipts   = { hash = "household_id", range = "sk" }
    ratelimit  = { hash = "key" }
    strikes    = { hash = "session_id" }
  }
}

resource "aws_dynamodb_table" "t" {
  for_each = local.tables

  name         = "${var.table_prefix}${each.key}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = each.value.hash
  range_key    = try(each.value.range, null)

  attribute {
    name = each.value.hash
    type = "S"
  }

  dynamic "attribute" {
    for_each = try(each.value.range, null) == null ? [] : [each.value.range]
    content {
      name = attribute.value
      type = "S"
    }
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = false
  }

  stream_enabled   = try(each.value.stream, false)
  stream_view_type = try(each.value.stream, false) ? "NEW_IMAGE" : null
}

locals {
  # table name -> ARN
  tarn = { for k, t in aws_dynamodb_table.t : k => t.arn }
}
