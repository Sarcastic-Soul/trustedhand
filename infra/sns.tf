resource "aws_sns_topic" "approvals" {
  name = "th-approvals"
}

resource "aws_sns_topic_subscription" "contact" {
  count     = var.trusted_contact_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.approvals.arn
  protocol  = "email"
  endpoint  = var.trusted_contact_email
}
