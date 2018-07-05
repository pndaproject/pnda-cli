# PNDA CLI

The PNDA CLI is the interface used to execute operational tasks on PNDA clusters. 

The PNDA CLI provides several back ends which automate the setup of PNDA with various orchestration technologies. The platform specific code is encapsulated in several different 'back ends' exposed to the end user via a unified CLI.

At present, the PNDA CLI supports four back ends -

- [Creating PNDA on AWS using CloudFormation](aws-cfn/README.md)
- [Creating PNDA on Openstack using Heat templates](heat-templates/README.md)
- [Creating PNDA on an existing server cluster](existing-machines/README.md)
- [Creating PNDA on VMware ESXi vSphere with Terraform (experimental)](terraform/README.md)

The operational tasks that are fully automated today are -

- Creating PNDA
- Expanding PNDA
- Deleting PNDA

Replacement of failed nodes is supported through a combination of manual steps and use of the 'expand' verb.
