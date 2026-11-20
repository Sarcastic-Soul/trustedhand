import os

import boto3
import pytest

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("TABLE_PREFIX", "th-")


@pytest.fixture
def aws():
    """Moto-backed DynamoDB with every TrustedHand table created."""
    from moto import mock_aws

    for k in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        os.environ.pop(k, None)
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    with mock_aws():
        from trustedhand import db
        from tests.tables import create_all

        db.clear_caches()
        create_all(boto3.client("dynamodb", region_name="us-east-1"))
        yield
        db.clear_caches()
