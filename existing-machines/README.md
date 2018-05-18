# Creating PNDA on an existing server cluster

## What does this mean
PNDA can be installed using the PNDA CLI onto pre-existing machines. In this mode the Cloud Formation and Openstack parts of the pnda-cli are disabled and it runs only the bootstrap and saltstack stages of PNDA creation.

The bootstrap stage involves running [shell scripts](../bootstrap-scripts) on each machine to install a saltstack cluster with each minion having the correct set of salt roles.

The saltstack stage involves running various [salt states](https://github.com/pndaproject/platform-salt) to install the PNDA software

## Overview
At a high level overview, creating PNDA on existing machines involves -

 - Finding some machines and ensuring they have an operating system, key based log in, appropriate disk drives and networking all set up before running the pnda-cli.
 - Writing a [json descriptor](production.json) that defines the IP address and type of each machine in the cluster.
 - Creating a PNDA mirror to serve the resources used to create PNDA.
 - Running the pnda-cli to install a saltstack cluster across the set of machines and then saltstack commands to install all of the PNDA software.

## Existing Machines Install Guide

A detailed walkthrough of the installation process is available in the [PNDA guide](https://github.com/pndaproject/pnda-guide/blob/develop/provisioning/server-cluster/PREPARE.md).

