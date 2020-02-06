from aws_cdk import (
    aws_cloudtrail as cloudtrail,
    aws_events as events,
    aws_events_targets as events_targets,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_sns as sns,
    aws_sns_subscriptions as subs,
    core,
)


class CloudTrailProtectionStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        user = iam.User(self, 'myuser',
                        managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name('AdministratorAccess')])

        trail = cloudtrail.Trail(self, 's3-account-activity',
                                 enable_file_validation=True,
                                 include_global_service_events=True,
                                 is_multi_region_trail=True,
                                 management_events=cloudtrail.ReadWriteType.ALL)

        fn = _lambda.Function(self, 'cloudtrail_reactivator',
                              description='Reactivates stopped CloudTrail logs',
                              code=_lambda.Code.from_asset('./lambda'),
                              handler='cloudtrail_reactivator.handler',
                              runtime=_lambda.Runtime.PYTHON_3_8,
                              initial_policy=[
                                  # Allow Lambda to re-activate CloudTrail logging.
                                  iam.PolicyStatement(resources=[trail.trail_arn],
                                                      actions=['cloudtrail:DescribeTrails',
                                                               'cloudtrail:GetTrailStatus',
                                                               'cloudtrail:StartLogging'],
                                                      effect=iam.Effect.ALLOW),
                                  # Allow Lambda to attach policies to user.
                                  iam.PolicyStatement(resources=[user.user_arn],
                                                      actions=['iam:AttachUserPolicy'],
                                                      effect=iam.Effect.ALLOW,
                                                      conditions={'ArnEquals': {"iam:PolicyARN": "arn:aws:iam::aws:policy/AWSDenyAll"}})
                              ])

        topic = sns.Topic(self, 'CloudTrailLoggingStateTransition')
        topic.add_subscription(subs.EmailSubscription('ENTER_YOUR_EMAIL@HERE.COM'))
        topic.grant_publish(fn)

        fn.add_environment('SNS_ARN', topic.topic_arn)

        # Event Pattern that defines the CloudTrail events that should trigger
        # the Lambda.
        event_pattern = events.EventPattern(source=['aws.cloudtrail'],
                                            detail={'eventName':   ['StopLogging',
                                                                    'DeleteTrail',
                                                                    'UpdateTrail',
                                                                    'RemoveTags',
                                                                    'AddTags',
                                                                    'CreateTrail',
                                                                    'StartLogging',
                                                                    'PutEventSelectors'],
                                                    'eventSource': ['cloudtrail.amazonaws.com']})
        trail.on_cloud_trail_event('CloudTrailStateChange',
                                   description='Detects CloudTrail log state changes',
                                   target=events_targets.LambdaFunction(fn),
                                   event_pattern=event_pattern)
