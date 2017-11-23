# Creating PNDA on an existing server cluster

## What does this mean
PNDA can be installed using the PNDA CLI onto pre-existing machines. In this mode the Cloud Formation parts of the pnda-cli are disabled and it runs only the bootstrap and saltstack stages of PNDA creation.

The bootstrap stage involves running [shell scripts](../bootstrap-scripts) on each machine to install a saltstack cluster with each minion having the correct set of salt roles.

The saltstack stage involves running various [salt states](https://github.com/pndaproject/platform-salt) to install the PNDA software

## Overview
By following the detailed guide below you can install PNDA onto a set of pre-existing machines. For a high level overview, this involves:

 - Finding some machines and ensuring they have an operating system, key based log in, appropriate disk drives and networking all set up before running the pnda-cli.
 - Writing a [json descriptor](pico.json) that defines the IP address and type of each machine in the cluster.
 - Creating a PNDA mirror to serve the resources used to create PNDA.
 - Running the pnda-cli to install a saltstack cluster across the set of machines and then saltstack commands to install all of the PNDA software.

## Existing Machines Install Guide
1. Obtain a set of machines on which to install PNDA. The requirements are:
   -  5 machines for pico. See [the PNDA guide](https://github.com/pndaproject/pnda-guide/blob/develop/provisioning/aws/PREPARE.md#required-resources) for suggested CPU and memory requirements for each machine.
   - 17 machines for standard.
   - On every machine, a log volume of 10GB.
   - On the data node, at least one volume of 35GB or more for data.
   - Review the [volume config mapping](../bootstrap-scripts/pico/volume-config.yaml) for your flavor so the number of disk volumes you have matches the ones being requested. By default the volumes are assigned out in descending size order, but it is possible to specify the device names and hard code the mappings in the volume config file. The disks can also be partitioned automatically. For an example of specifying device names and partitioning see [this volume config file](../bootstrap-scripts/production/volume-config.yaml).
2. Install either Ubuntu 14.04 or Redhat Enterprise Linux 7 on all machines
3. If not already in place, setup ssh key based access to the machines.
   - create an RSA keypair to use to access the machines:

        ```sh
        ssh-keygen -b 2048 -t rsa -f mykey.pem -q -N ""
        ```
   - create a sudo user `<username>` on each machine:

        ```sh
        sudo su
        adduser <username> --disabled-password --gecos ""
        echo <username> ALL=NOPASSWD: ALL >> /etc/sudoers
        ```
   - allow login for that user with the created key on each machine:

        ```sh
        mkdir /home/<username>/.ssh
        cat mykey.pem.pub >> /home/<username>/.ssh/authorized_keys
        ```
4. Copy `pnda_env_example.yaml` to create `pnda_env.yaml`
5. Edit `pnda_env.yaml` with `ec2_access: OS_USER: <username>`
6. Edit `pnda_env.yaml` with `pnda_application_repo: PR_FS_TYPE: local`
7. (Optional) Edit `pnda_env.yaml` with `ntp: NTP_SERVERS: my.ntp.server` if internet based NTP servers are not reachable from your environment.
8. Create a [pnda mirror](https://github.com/pndaproject/pnda/tree/develop/mirror) and [build the PNDA binaries](https://github.com/pndaproject/pnda/tree/develop/build) and edit `pnda_env.yaml` with the address of it: `mirrors: PNDA_MIRROR: http://mirror_address`. Please use a clean, internet connected machine to build the mirror and the PNDA binaries. If the machine is not clean (meaning no additional deb or rpm packages have ever been added using apt-get/yum) the dependency calculations can be incorrect and the mirror will be missing packages, or will fail entirely.
9. Edit existing-machines/pico.json or existing-machines/standard.json (or copies of these files) with the IP addresses of these machines. `ip_address` must be reachable from each machine but does not have to be reachable from where the cli is run, `public_ip_address` (set for the bastion node only) must be reachable from where the cli is run. This allows the bastion to act as a gateway into a private network. Add or remove datanodes, kafka nodes, zookeeper nodes (standard only), opentsdb nodes (standard only) to match the number of machines that you have.
10. Ensure all ports are open between the machines and port 22 is open externally on the bastion machine
11. Install pip packages required by the CLI

    ```sh
    # make sure to use pip2 or the install will fail later on
    cd cli
    sudo pip2 install -r requirements.txt
    ```
12. Run pnda-cli to install PNDA with the -m flag for existing-machines installation.

    ```sh
    cli/pnda-cli.py -e pnda -s mykey -f pico -m 'existing-machines/my-pico.json' create
    cli/pnda-cli.py -e pnda -s mykey -f standard -m 'existing-machines/my-standard.json' create
    ```
