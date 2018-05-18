# PNDA CLI

The PNDA CLI is the interface used to execute operational tasks on PNDA clusters. 

The vision for this sub-project is that it eventually replaces all the individual 'template' repositories in PNDA with one common code base, presenting the end user with a unified interface to several different 'back ends'.

At present, the PNDA CLI supports three back ends -

- [Creating PNDA on AWS using CloudFormation](aws-cfn/README.md)
- [Creating PNDA on Openstack using Heat templates](heat-templates/README.md)
- [Creating PNDA on an existing server cluster](existing-machines/README.md)

The operational tasks that are fully automated today are -

- Creating PNDA
- Expanding PNDA
- Deleting PNDA

Replacement of failed nodes is supported through a combination of manual steps and use of the 'expand' verb.
