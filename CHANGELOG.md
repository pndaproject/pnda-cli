# Change Log
All notable changes to this project will be documented in this file.

## [Unreleased]
### Changed
- PNDA-3583: hadoop distro is now part of grains
- PNDA-3365: remove unnecessary explicit hostfile setup on bastion

### Fixed
- PNDA-3534: Make iptables injection script idempotent.
- PNDA-3552: Creation time improvements for large clusters when there is no bastion.

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
- PNDA-3530: Ambari version 2.6.0.0 and HDP version 2.6.3.0
- PNDA-3487: /tmp is now tmpfs for production

### Fixed
- PNDA-3499: Cleanup CHANGELOG with missing release info.
- PNDA-3200: socks_proxy script reuses existing ssh-agent instead of launching a new one if possible
- PNDA-3199: Make socks proxy script executable
- PNDA-3424: Add a retry to AWS API calls to work around SSL timeout errors
- PNDA-3377: fix issue on check config which required descriptor file

## [FORK]
- Applied annotation tag where pndaproject/pnda-aws-templates has been forked.
