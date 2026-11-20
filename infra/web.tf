# Private S3 bucket behind CloudFront (OAC). web/*.html|css|js uploaded from the repo.

locals {
  web_dir = "${path.module}/../web"

  content_types = {
    html  = "text/html; charset=utf-8"
    css   = "text/css; charset=utf-8"
    js    = "application/javascript; charset=utf-8"
    json  = "application/json"
    svg   = "image/svg+xml"
    png   = "image/png"
    jpg   = "image/jpeg"
    ico   = "image/x-icon"
    txt   = "text/plain; charset=utf-8"
    woff2 = "font/woff2"
  }

  # config.js is generated below, so it is left out of the file set.
  web_files = toset([
    for f in fileset(local.web_dir, "**") : f
    if f != "config.js" && f != "config.local.js" && !startswith(f, "dev/") && contains(keys(local.content_types), reverse(split(".", f))[0])
  ])
}

resource "aws_s3_bucket" "web" {
  bucket        = "th-web-${local.account}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "web" {
  bucket                  = aws_s3_bucket.web.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "web" {
  bucket = aws_s3_bucket.web.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_cloudfront_origin_access_control" "web" {
  name                              = "th-web-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

resource "aws_cloudfront_distribution" "web" {
  enabled             = true
  comment             = "TrustedHand web"
  default_root_object = "index.html"
  price_class         = "PriceClass_100"
  http_version        = "http2and3"

  origin {
    origin_id                = "web"
    domain_name              = aws_s3_bucket.web.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.web.id
  }

  default_cache_behavior {
    target_origin_id       = "web"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true
    cache_policy_id        = data.aws_cloudfront_cache_policy.disabled.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

data "aws_iam_policy_document" "web" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.web.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.web.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "web" {
  bucket     = aws_s3_bucket.web.id
  policy     = data.aws_iam_policy_document.web.json
  depends_on = [aws_s3_bucket_public_access_block.web]
}

resource "aws_s3_object" "files" {
  for_each = local.web_files

  bucket        = aws_s3_bucket.web.id
  key           = each.value
  source        = "${local.web_dir}/${each.value}"
  etag          = filemd5("${local.web_dir}/${each.value}")
  content_type  = local.content_types[reverse(split(".", each.value))[0]]
  cache_control = "no-cache"
}

resource "aws_s3_object" "config" {
  bucket        = aws_s3_bucket.web.id
  key           = "config.js"
  content       = "window.TH_CONFIG = {apiBase: \"${aws_apigatewayv2_api.api.api_endpoint}\", chatUrl: \"${aws_lambda_function_url.chat.function_url}\"};\n"
  content_type  = "application/javascript; charset=utf-8"
  cache_control = "no-cache"
}
