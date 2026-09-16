"""Assume a role via STS and return a boto3 session. No hardcoding: if the
assume fails, the caller sees the real error."""
import boto3

def session_for(role_arn: str, region: str, session_name: str = "apt-poc"):
    sts = boto3.client("sts", region_name=region)
    resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    c = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=c["AccessKeyId"],
        aws_secret_access_key=c["SecretAccessKey"],
        aws_session_token=c["SessionToken"],
        region_name=region,
    )
