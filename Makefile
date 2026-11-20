# TrustedHand build and deploy. All AWS commands use the sarcastic-soul profile.
PROFILE ?= sarcastic-soul
REGION  ?= us-east-1
TF      := terraform -chdir=infra
AWS_PROFILE_ARG := --profile $(PROFILE) --region $(REGION)
export TF_PLUGIN_CACHE_DIR ?= $(HOME)/.terraform.d/plugin-cache
export TMPDIR ?= $(HOME)/.cache/tftmp
# Terraform's AWS provider reads the profile from var.aws_profile (default
# sarcastic-soul); harness.py and the aws CLI calls below use $(PROFILE).
TFVARS  := -var aws_profile=$(PROFILE)

.PHONY: test build layer plan deploy harness destroy web init fmt

test:
	uv run pytest -q

init:
	mkdir -p $(TMPDIR) $(TF_PLUGIN_CACHE_DIR)
	$(TF) init -input=false

# Lambda zips (fails clearly if a handler is missing) plus the boto3 layer.
build: layer
	uv run python scripts/package.py

# boto3 is pure python, so a plain install works for python 3.13 arm64.
layer:
	rm -rf build/layer
	mkdir -p build/layer/python
	uv pip install --quiet --target build/layer/python --python 3.13 boto3 botocore
	find build/layer -name __pycache__ -type d -prune -exec rm -rf {} +
	find build/layer -name '*.dist-info' -type d -prune -exec rm -rf {} +

plan: build init
	$(TF) plan -input=false $(TFVARS)

deploy: build init
	$(TF) apply -auto-approve -input=false $(TFVARS)
	uv run python infra/harness.py apply

harness:
	uv run python infra/harness.py apply

destroy: init
	-uv run python infra/harness.py destroy
	$(TF) destroy -auto-approve -input=false $(TFVARS)

# Re-upload web files and clear the CloudFront cache (config.js is made by Terraform).
web:
	BUCKET=$$($(TF) output -raw web_bucket) && \
	DIST=$$($(TF) output -raw cloudfront_distribution_id) && \
	aws s3 sync web/ s3://$$BUCKET/ --exclude config.js --exclude config.local.js --exclude 'dev/*' --cache-control no-cache $(AWS_PROFILE_ARG) && \
	aws cloudfront create-invalidation --distribution-id $$DIST --paths '/*' $(AWS_PROFILE_ARG) --query Invalidation.Id --output text

fmt:
	$(TF) fmt
