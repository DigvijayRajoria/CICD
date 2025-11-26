# CICD
This README documents step-by-step instructions, Terraform & CloudFormation examples, AWS CLI commands, security notes and testing for creating an IAM user who:

Has EC2 permissions via an attached IAM policy (directly on the user)

Has IAM permissions via membership of an IAM group (user inherits group permissions)

Table of contents

Overview

Security & design decisions

Prerequisites

Resources this README will create

AWS Console step-by-step (recommended for one-off/manual setup)

AWS CLI commands (copy & run)

Terraform example (recommended for infra-as-code)

CloudFormation example (YAML)

Least-privilege advice & common policies

How to test the setup

Cleanup / rollback commands

Change log

License

1) Overview

We want to create an IAM user (example name: dev-ec2-user) with two kinds of permissions:

EC2 access: a policy attached directly to the user (so changes to that policy affect the user immediately). Example policy here gives broad EC2 permissions; in production you should scope it down.

IAM access: the user is added to a group (IAM-Admins) which has IAM-related permissions (read-only or full access depending on your risk tolerance). This separates responsibilities and makes governance easier.

This README shows Console steps, CLI commands, and IaC snippets.

2) Security & design decisions

Separation of privileges: EC2 permission is attached directly to the user (so it’s explicit). IAM permission is via a group (so multiple users can inherit IAM privileges centrally).

Prefer least privilege: the examples here include ec2:* and IAMFullAccess to be clear and simple. For production, restrict actions and Resource ARNs.

Use MFA: require console MFA for users who can change IAM or manage credentials.

Use long-lived policies sparingly: prefer managed policies versioned in IaC.

3) Prerequisites

AWS account with a user that has permission to create IAM users, groups, policies.

aws CLI configured (aws configure) for the administrator account or role.

Terraform (optional) — terraform CLI installed if using Terraform section.

CloudFormation (optional) — you may use the AWS Console or aws cloudformation.

4) Resources this README will create (naming examples)

IAM Group: IAM-Admins

IAM Policy (EC2): EC2FullAccess-Custom

IAM User: dev-ec2-user

Attachments:

Add dev-ec2-user to group IAM-Admins (inherits group's IAM permissions)

Attach EC2FullAccess-Custom policy directly to dev-ec2-user

Replace names with your org conventions.

5) AWS Console step-by-step

Create an IAM Group

IAM → User groups → Create group

Group name: IAM-Admins

Attach policy: choose IAMReadOnlyAccess or IAMFullAccess (choose carefully)

Create group

Create the EC2 policy

IAM → Policies → Create policy → JSON

Paste the example JSON policy (see JSON example below)

Review → Name: EC2FullAccess-Custom → Create

Create the IAM user

IAM → Users → Add users

User name: dev-ec2-user

Select access type: AWS Management Console access (and/or Programmatic access if CLI/SDK needed)

Set password and require user to reset password

Next: Permissions → Add user to group: select IAM-Admins

Next: Attach existing policies directly → choose EC2FullAccess-Custom

Create user

MFA & password policy

Configure MFA for the user or use IAM password policy with required length/rotation

6) AWS CLI — copy & run

Run these commands from an admin session. Replace placeholders (e.g., ACCOUNT_ALIAS, names) as needed.

Create group

aws iam create-group --group-name IAM-Admins

(Optional) Attach IAMFullAccess to group

# Attach AWS managed policy (be careful: gives full IAM access)
aws iam attach-group-policy --group-name IAM-Admins --policy-arn arn:aws:iam::aws:policy/IAMFullAccess


# OR for read-only
aws iam attach-group-policy --group-name IAM-Admins --policy-arn arn:aws:iam::aws:policy/IAMReadOnlyAccess

Create EC2 policy JSON locally

Save this as ec2-full-policy.json (insecure broad example — narrow in prod):

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ec2:*",
      "Resource": "*"
    }
  ]
}

Create the custom policy

aws iam create-policy --policy-name EC2FullAccess-Custom --policy-document file://ec2-full-policy.json

Create the IAM user

# Create user with console and programmatic (access keys) access if needed
aws iam create-user --user-name dev-ec2-user


# Create login profile (console password). This sets an initial password and requires change-on-first-login if you want.
aws iam create-login-profile --user-name dev-ec2-user --password "ChangeMe123!" --password-reset-required


# If you need programmatic access keys (CLI/API), create access key
aws iam create-access-key --user-name dev-ec2-user

Add user to group

aws iam add-user-to-group --user-name dev-ec2-user --group-name IAM-Admins

Attach policy directly to user

# Find policy ARN from the create-policy output or list-policies
# Example ARN format: arn:aws:iam::123456789012:policy/EC2FullAccess-Custom
aws iam attach-user-policy --user-name dev-ec2-user --policy-arn arn:aws:iam::123456789012:policy/EC2FullAccess-Custom

Set MFA requirement (console)

For security, require MFA. This is usually done by instructing the user to configure an MFA device on first login or setting up an account policy that enforces MFA for sensitive actions.

7) Terraform example (minimal)

Save this as iam_ec2_user.tf and run terraform init / terraform apply.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}


provider "aws" {
  region = "us-east-1"
}


resource "aws_iam_group" "iam_admins" {
  name = "IAM-Admins"
}


resource "aws_iam_group_policy_attachment" "attach_iam_full" {
  group      = aws_iam_group.iam_admins.name
  policy_arn = "arn:aws:iam::aws:policy/IAMReadOnlyAccess" # or IAMFullAccess
}


resource "aws_iam_user" "dev_ec2_user" {
  name = "dev-ec2-user"
}


resource "aws_iam_user_group_membership" "membership" {
  user = aws_iam_user.dev_ec2_user.name
  groups = [aws_iam_group.iam_admins.name]
}


resource "aws_iam_policy" "ec2_policy" {
  name        = "EC2FullAccess-Custom"
  description = "Custom EC2 policy for developer"


  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "ec2:*"
        Effect = "Allow"
        Resource = "*"
      }
    ]
  })
}


resource "aws_iam_user_policy_attachment" "attach_ec2_to_user" {
  user       = aws_iam_user.dev_ec2_user.name
  policy_arn = aws_iam_policy.ec2_policy.arn
}


# Optionally create access keys (be cautious about storing secrets)
resource "aws_iam_access_key" "dev_user_key" {
  user = aws_iam_user.dev_ec2_user.name
}

Notes:

Terraform will show the access key secret only at creation; handle it securely.

Prefer to use IAM Roles for EC2 instances rather than distributing access keys.

8) CloudFormation (YAML) minimal example

Save as iam-user-ec2-iam.yml and deploy using CloudFormation.

AWSTemplateFormatVersion: '2010-09-09'
Description: IAM user with EC2 policy and IAM group membership
Resources:
  IAMAdminsGroup:
    Type: AWS::IAM::Group
    Properties:
      GroupName: IAM-Admins
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/IAMReadOnlyAccess # or IAMFullAccess


  EC2FullAccessCustomPolicy:
    Type: AWS::IAM::Policy
    Properties:
      PolicyName: EC2FullAccess-Custom
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action: 'ec2:*'
            Resource: '*'
      Roles: []
      Users: []


  DevEc2User:
    Type: AWS::IAM::User
    Properties:
      UserName: dev-ec2-user


  DevUserToGroup:
    Type: AWS::IAM::UserToGroupAddition
    Properties:
      GroupName: !Ref IAMAdminsGroup
      Users:
        - !Ref DevEc2User


  AttachPolicyToUser:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      Description: Attach EC2 policy to user via inline managed policy
      Roles: []
      Users:
        - !Ref DevEc2User
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action: 'ec2:*'
            Resource: '*'

CloudFormation has several flavors of creating policies; above is a quick structure — adapt to your org conventions.

9) Least-privilege advice & common policy examples

Don’t use ec2:* in production if you can avoid it. Replace with explicit actions and resource ARNs. Examples:

Manage EC2 lifecycle (start/stop/describe)

{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:StartInstances",
        "ec2:StopInstances",
        "ec2:RebootInstances"
      ],
      "Resource": "*"
    }
  ]
}

Narrow to resource-level by using instance ARNs or tags where possible, e.g. arn:aws:ec2:region:account:instance/instance-id or condition on tags.

IAM actions: For group permissions, prefer IAMReadOnlyAccess for view-only tasks. If users must create or manage users/roles, use narrowly scoped policies that only allow designated actions (e.g., iam:CreateUser, iam:AttachUserPolicy), not iam:*.

Use permissions boundaries for users who can create IAM principals, preventing privilege escalation.

10) How to test the setup

Login as the new user (console)

Confirm the user can sign in.

Confirm user can perform EC2 actions allowed by the policy (e.g., list instances).

Confirm user inherits IAM actions from the group (if IAMReadOnlyAccess, they should be able to list users but not create them).

Programmatic test (if access keys created)

Configure a local profile:

aws configure --profile dev-ec2-user
# use the AccessKeyId and SecretAccessKey returned from create-access-key

Run a sample command: aws ec2 describe-instances --profile dev-ec2-user

Negative testing

Try an action that should be disallowed (e.g., if IAMReadOnlyAccess attached, try creating a new IAM user) and confirm it fails with AccessDenied.
