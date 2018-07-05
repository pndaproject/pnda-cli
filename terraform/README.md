# Creating PNDA on VMware ESXi vSphere with Terraform (experimental)

## What does this mean
PNDA can be installed using the PNDA CLI onto VMWare vSphere. Terraform (link) is used

## Overview
At a high level overview, creating PNDA on vSphere involves -

 - Installing Terraform
 - Setting up an ESXi vSphere cluster
 - Creating a PNDA mirror to serve the resources used to create PNDA.
 - Running the pnda-cli which creates the virtual machines machines and runs the saltstack commands to install all of the PNDA software.

## VMware ESXi vSphere with Terraform Install Guide

TODO: When running through this for testing fill out this guide with the steps taken.

