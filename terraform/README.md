# Creating PNDA on VMware ESXi vSphere with Terraform (experimental)

## Overview
PNDA can be installed using the PNDA CLI onto VMWare vSphere. The PNDA CLI uses [Terraform](https://www.terraform.io) to create the virtual machines.

At a high level overview, creating PNDA on vSphere involves -

 - Installing [Terraform](https://www.terraform.io) and adding it to the path.
 - Setting up an ESXi vSphere cluster. Outside the scope of this guide.
 - Creating a PNDA mirror to serve the resources used to create PNDA.
 - Running the pnda-cli which creates the virtual machines and runs the saltstack commands to install all of the PNDA software.

## VMware ESXi vSphere with Terraform Install Guide

A detailed walkthrough of the installation process is available in the [PNDA guide](https://github.com/pndaproject/pnda-guide/blob/develop/provisioning/vmware/CREATE.md).

