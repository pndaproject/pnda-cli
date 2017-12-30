# Change Log
All notable changes to this project will be documented in this file.

## [Unreleased]
### Added
- PNDA-3127: PNDA-3127: Post ingress aggregation for Kafka datasets
- PNDA-3299: Support multiple NTP servers properly
- PNDA-3599: Console output indicating any cloud formation stack errors
- PNDA-3598: Add a pre-check to validate the AWS region

### Changed
- PNDA-3583: hadoop distro is now part of grains
- PNDA-3365: remove unnecessary explicit hostfile setup on bastion
- PNDA-3530: Ambari version 2.6.0.0 and HDP version 2.6.3.0
- PNDA-3487: /tmp is now tmpfs for production
- PNDA-3602: Update boto requirement to 2.48.0 for updated ec2 region support

### Fixed
- PNDA-3534: Make iptables injection script idempotent.
- PNDA-3552: Creation time improvements for large clusters when there is no bastion.
- Fork: Fixed issue with missing /etc/cloud directory failing install on baremetal

## [1.0.0] 2017-11-24
### Added
- PNDA-3160: Added support for creating PNDA on existing server clusters
- PNDA-1960: Make Kafkat available on nodes as option for Kafka management at CLI
- PNDA-2955: Add pnda_env.yaml setting for choosing hadoop distro to install
- PNDA-3302: Upgrade edge flavor on pico
- PNDA-3218: Add iprejecter to enable offline env
- PNDA-3314: Add new flavor 'production' designed for larger, bare metal clusters
- PNDA-3484: Add CentOS support

### Changed
- PNDA-3186: Refactored code into CLI for creating PNDAs on many platforms (pnda-cli)
- PNDA-2965: Rename `cloudera_*` role grains to `hadoop_*`
- PNDA-3215: Remove EPEL repository
- PNDA-3180: When expanding a cluster limit the operations to strictly required steps on specific nodes
- PNDA-3444: Disallow uppercase letters in the cluster names due to AMBARI-22361 affecting HDP.

### Fixed
- PNDA-3499: Cleanup CHANGELOG with missing release info.
- PNDA-3200: socks_proxy script reuses existing ssh-agent instead of launching a new one if possible
- PNDA-3199: Make socks proxy script executable
- PNDA-3424: Add a retry to AWS API calls to work around SSL timeout errors
- PNDA-3377: fix issue on check config which required descriptor file

## [FORK]
- Applied annotation tag where pndaproject/pnda-aws-templates has been forked.
