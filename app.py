#!/usr/bin/env python3

from aws_cdk import core

from cloudtrail_protection.cloudtrail_protection_stack import CloudTrailProtectionStack

env_DE = core.Environment(region='eu-central-1', account=core.Aws.ACCOUNT_ID)

app = core.App()

CloudTrailProtectionStack(app, 'cloudtrail-protection', env=env_DE)

app.synth()
