# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# Modifications copyright (C) 2020 Milen Grossmann
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either expressed or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
# Description: Lambda function that sends notification on AWS CloudTrail changes,
# blocks the issuing user and reactivates the disabled CloudTrail log.
#
# cloudtrail_reactivator.py
#
# Author: Sudhanshu Malhotra, sudmal@amazon.com
# Date: 2017-06-08
# Modifications: Milen Grossmann, milo0@posteo.de
# Date: 2020-02-06
#

import json
import logging
import os

import boto3
import botocore.session
from botocore.exceptions import ClientError

session = botocore.session.get_session()

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# Lambda function for automatic reactivation of AWS CloudTrail logs. All
# notifications about changes to the trail will be published to an SNS topic.
def handler(event, context):
    logger.setLevel(logging.DEBUG)
    event_name = event['detail']['eventName']
    # Receive SNS Topic ARN via environment variables.
    sns_arn = os.environ['SNS_ARN']
    logger.debug(f'Received event name: {event_name}')
    logger.debug(f'Event JSON: {event}')
    logger.debug(f'SNS ARN: {sns_arn}')
    sns_client = boto3.client('sns')
    iam_client = boto3.client('iam')

    # If CloudTrail logging is disabled, Lambda will send a notification
    # to SNS and revert it back to enabled state.
    # Note: The reactivation will generate another SNS notification, because
    # the Lambda executes 'EnableLogging' on the trail.
    if event_name == 'StopLogging':
        cloudtrail_arn = event['detail']['requestParameters']['name']
        user_name = event['detail']['userIdentity']['userName']
        logger.info(f'AWS CloudTrail logging disabled for ARN {cloudtrail_arn}. '
                    f'Initiating reactivation...'
                    f'Revoking all permissions for user {user_name}...')

        # Send notification that AWS CloudTrail has been disabled.
        sns_publish = sns_client.publish(
            TargetArn=sns_arn,
            Subject=f'CloudTrail event "{event_name}" invoked by user "{user_name}".'
                    f'Blocking user and initiating CloudTrail log reactivation...',
            Message=json.dumps({'default': json.dumps(event)}),
            MessageStructure='json'
        )

        # Reactivate CloudTrail logging and revoke all permissions from user.
        try:
            client = boto3.client('cloudtrail')
            enable_logging = client.start_logging(Name=cloudtrail_arn)
            iam_client.attach_user_policy(UserName=user_name,
                                          PolicyArn='arn:aws:iam::aws:policy/AWSDenyAll')
            logger.debug(f'Response to CloudTrail logging reactivation {enable_logging}.')
        except ClientError as e:
            logger.error(f'An error occurred: {e}')
    # Any event other than "StopLogging" only sends a notification to the
    # SNS topic subscribers.
    else:
        logger.info(f'CloudTrail event "{event_name}" received. '
                    f'Sending notification to SNS topic...')
        try:
            sns_publish = sns_client.publish(
                TargetArn=sns_arn,
                Subject=f'CloudTrail event "{event_name}" received.',
                Message=json.dumps({'default': json.dumps(event)}),
                MessageStructure='json'
            )
            logger.debug(f'SNS publish response: {sns_publish}')
        except ClientError as e:
            logger.error(f'An error occurred: {e}')
