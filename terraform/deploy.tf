provider "vsphere" {
  user           = "${var.vsphere_user}"
  password       = "${var.vsphere_password}"
  vsphere_server = "${var.vsphere_server}"

  allow_unverified_ssl = true
}
data "vsphere_datacenter" "dc" {
  name = "${var.datacenter}"
}
data "vsphere_datastore" "datastore" {
  name          = "${var.DS}"
  datacenter_id = "${data.vsphere_datacenter.dc.id}"
}
data "vsphere_compute_cluster" "cluster" {
  name          = "${var.cluster_name}"
  datacenter_id = "${data.vsphere_datacenter.dc.id}"
}
data "vsphere_network" "public" {
  name          = "${var.public_network}"
  datacenter_id = "${data.vsphere_datacenter.dc.id}"
}
data "vsphere_virtual_machine" "pnda_template_base" {
  name          = "${var.pnda_template_base}"
  datacenter_id = "${data.vsphere_datacenter.dc.id}"
}
data "vsphere_virtual_machine" "pnda_template_datanode" {
  name          = "${var.pnda_template_datanode}"
  datacenter_id = "${data.vsphere_datacenter.dc.id}"
}
data "vsphere_virtual_machine" "pnda_template_kafka" {
  name          = "${var.pnda_template_kafka}"
  datacenter_id = "${data.vsphere_datacenter.dc.id}"
}

// Datanode Node
resource "vsphere_virtual_machine" "datanode" {
  count                      = "${var.datanode_count}"
  name                       = "${var.pnda_cluster_name}-hadoop-dn-${count.index}"
  resource_pool_id           = "${data.vsphere_compute_cluster.cluster.resource_pool_id}"
  datastore_id               = "${data.vsphere_datastore.datastore.id}"
  folder                     = "${var.vsphere_folder}"
  num_cpus                   = "${var.datanode_cpu_count}"
  memory                     = "${var.datanode_memory_count}"
  guest_id                   = "${var.guest_id}"
  scsi_type                  = "${data.vsphere_virtual_machine.pnda_template_datanode.scsi_type}"
  wait_for_guest_net_timeout = 15
  network_interface {
    network_id = "${data.vsphere_network.public.id}"
  }
  disk {
    label            = "disk0"
    size             = "${data.vsphere_virtual_machine.pnda_template_datanode.disks.0.size}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_datanode.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_datanode.disks.0.eagerly_scrub}"
    unit_number      = 0
  }
  disk {
    label            = "disk1"
    size             = "${var.datanode_logvolumesize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_datanode.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_datanode.disks.0.eagerly_scrub}"
    unit_number      = 1
  }
  disk {
    label            = "disk2"
    size             = "${var.datanode_data1mountsize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_datanode.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_datanode.disks.0.eagerly_scrub}"
    unit_number      = 2
  }
  disk {
    label            = "disk3"
    size             = "${var.datanode_data2mountsize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_datanode.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_datanode.disks.0.eagerly_scrub}"
    unit_number      = 3
  }
  clone {
    template_uuid = "${data.vsphere_virtual_machine.pnda_template_datanode.id}"
    /*customize {
      linux_options {
        host_name = "datanode-${count.index}"
        domain    = "pnda.local"
      }
      network_interface {}
    }*/
  }
  provisioner "file" {
    source      = "./terraform/scripts"
    destination = "/tmp"
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = "ls /tmp",
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/scripts/*.sh",
      "/tmp/scripts/ssh_conf.sh",
      "/tmp/scripts/authorized_keys.sh",
      "rm -rf /tmp/scripts",
      "passwd -d root",
      "userdel -r centos"
    ],
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
}

// Kafka Node
resource "vsphere_virtual_machine" "kafka" {
  count                      = "${var.kafkanode_count}"
  name                       = "${var.pnda_cluster_name}-kafka-${count.index}"
  resource_pool_id           = "${data.vsphere_compute_cluster.cluster.resource_pool_id}"
  datastore_id               = "${data.vsphere_datastore.datastore.id}"
  folder                     = "${var.vsphere_folder}"
  num_cpus                   = "${var.kafka_cpu_count}"
  memory                     = "${var.kafkanode_memory_count}"
  guest_id                   = "${var.guest_id}"
  scsi_type                  = "${data.vsphere_virtual_machine.pnda_template_kafka.scsi_type}"
  wait_for_guest_net_timeout = 15
  network_interface {
    network_id = "${data.vsphere_network.public.id}"
  }
  disk {
    label            = "disk0"
    size             = "${data.vsphere_virtual_machine.pnda_template_kafka.disks.0.size}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_kafka.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_kafka.disks.0.eagerly_scrub}"
    unit_number      = 0
  }
  disk {
    label            = "disk1"
    size             = "${var.kafka_logvolumesize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_kafka.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_kafka.disks.0.eagerly_scrub}"
    unit_number      = 1
  }
  disk {
    label            = "disk2"
    size             = "${var.kafka_datamountsize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_kafka.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_kafka.disks.0.eagerly_scrub}"
    unit_number      = 2
  }
  disk {
    label            = "disk3"
    size             = "${var.kafka_data2mountsize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_kafka.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_kafka.disks.0.eagerly_scrub}"
    unit_number      = 3
  }
  clone {
    template_uuid = "${data.vsphere_virtual_machine.pnda_template_kafka.id}"
    /*customize {
      linux_options {
        host_name = "kafka-${count.index}"
        domain    = "pnda.local"
      }
      network_interface {}
    }*/
  }
  provisioner "file" {
    source      = "./terraform/scripts"
    destination = "/tmp"
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = "ls /tmp",
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/scripts/*.sh",
      "/tmp/scripts/ssh_conf.sh",
      "/tmp/scripts/authorized_keys.sh",
      "rm -rf /tmp/scripts",
      "passwd -d root",
      "userdel -r centos"
    ],
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
}

// Zookeeper Node
resource "vsphere_virtual_machine" "zookeeper" {
  count                      = "${var.zookeeper_count}"
  name                       = "${var.pnda_cluster_name}-zk-${count.index}"
  resource_pool_id           = "${data.vsphere_compute_cluster.cluster.resource_pool_id}"
  datastore_id               = "${data.vsphere_datastore.datastore.id}"
  folder                     = "${var.vsphere_folder}"
  num_cpus                   = "${var.zookeeper_cpu_count}"
  memory                     = "${var.zookeeper_memory_count}"
  guest_id                   = "${var.guest_id}"
  scsi_type                  = "${data.vsphere_virtual_machine.pnda_template_base.scsi_type}"
  wait_for_guest_net_timeout = 15
  network_interface {
    network_id = "${data.vsphere_network.public.id}"
  }
  disk {
    label            = "disk0"
    size             = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.size}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 0
  }
  disk {
    label            = "disk1"
    size             = "${var.zookeeper_logvolumesize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 1
  }
  disk {
    label            = "disk2"
    size             = "${var.zookeeper_datamountsize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 2
  }
  clone {
    template_uuid = "${data.vsphere_virtual_machine.pnda_template_base.id}"
    /*customize {
      linux_options {
        host_name = "zk-${count.index}"
        domain    = "pnda.local"
      }
      network_interface {}
    }*/
  }
  provisioner "file" {
    source      = "./terraform/scripts"
    destination = "/tmp"
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = "ls /tmp",
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/scripts/*.sh",
      "/tmp/scripts/ssh_conf.sh",
      "/tmp/scripts/authorized_keys.sh",
      "rm -rf /tmp/scripts",
      "passwd -d root",
      "userdel -r centos"
    ],
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
}

// Hadoop Management Nodes
resource "vsphere_virtual_machine" "management" {
  count                      = "${var.management_count}"
  name                       = "${var.pnda_cluster_name}-hadoop-mgr-${count.index}"
  resource_pool_id           = "${data.vsphere_compute_cluster.cluster.resource_pool_id}"
  datastore_id               = "${data.vsphere_datastore.datastore.id}"
  folder                     = "${var.vsphere_folder}"
  num_cpus                   = "${var.management_cpu_count}"
  memory                     = "${var.managementnode_memory_count}"
  guest_id                   = "${var.guest_id}"
  scsi_type                  = "${data.vsphere_virtual_machine.pnda_template_base.scsi_type}"
  wait_for_guest_net_timeout = 15
  network_interface {
    network_id = "${data.vsphere_network.public.id}"
  }
  disk {
    label            = "disk0"
    size             = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.size}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 0
  }
  disk {
    label            = "disk1"
    size             = "${var.management_logvolumesize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 1
  }
  disk {
    label            = "disk2"
    size             = "${var.management_datamountsize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 2
  }
  clone {
    template_uuid = "${data.vsphere_virtual_machine.pnda_template_base.id}"
    /*customize {
      linux_options {
        host_name = "hadoop-mgr-${count.index}"
        domain    = "pnda.local"
      }
      network_interface {}
    }*/
  }
  provisioner "file" {
    source      = "./terraform/scripts"
    destination = "/tmp"
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = "ls /tmp",
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/scripts/*.sh",
      "/tmp/scripts/ssh_conf.sh",
      "/tmp/scripts/authorized_keys.sh",
      "rm -rf /tmp/scripts",
      "passwd -d root",
      "userdel -r centos"
    ],
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
}

// Hadoop Cluster Manager Node
resource "vsphere_virtual_machine" "cm" {
  count                      = "${var.cm_count}"
  name                       = "${var.pnda_cluster_name}-hadoop-cm-${count.index}"
  resource_pool_id           = "${data.vsphere_compute_cluster.cluster.resource_pool_id}"
  datastore_id               = "${data.vsphere_datastore.datastore.id}"
  folder                     = "${var.vsphere_folder}"
  num_cpus                   = "${var.cm_cpu_count}"
  memory                     = "${var.cm_memory_count}"
  guest_id                   = "${var.guest_id}"
  scsi_type                  = "${data.vsphere_virtual_machine.pnda_template_base.scsi_type}"
  wait_for_guest_net_timeout = 15
  network_interface {
    network_id = "${data.vsphere_network.public.id}"
  }
  disk {
    label            = "disk0"
    size             = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.size}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 0
  }
  disk {
    label            = "disk1"
    size             = "${var.cm_logvolumesize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 1
  }
  disk {
    label            = "disk2"
    size             = "${var.cm_datamountsize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 2
  }
  clone {
    template_uuid = "${data.vsphere_virtual_machine.pnda_template_base.id}"
    /*customize {
      linux_options {
        host_name = "hadoop-cm-${count.index}"
        domain    = "pnda.local"
      }
      network_interface {}
    }*/
  }
  provisioner "file" {
    source      = "./terraform/scripts"
    destination = "/tmp"
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = "ls /tmp",
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/scripts/*.sh",
      "/tmp/scripts/ssh_conf.sh",
      "/tmp/scripts/authorized_keys.sh",
      "rm -rf /tmp/scripts",
      "passwd -d root",
      "userdel -r centos"
    ],
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
}

// Hadoop Edge Node
resource "vsphere_virtual_machine" "edge" {
  count                      = "${var.edge_node_count}"
  name                       = "${var.pnda_cluster_name}-hadoop-edge-${count.index}"
  resource_pool_id           = "${data.vsphere_compute_cluster.cluster.resource_pool_id}"
  datastore_id               = "${data.vsphere_datastore.datastore.id}"
  folder                     = "${var.vsphere_folder}"
  num_cpus                   = "${var.edgenode_cpu_count}"
  memory                     = "${var.edgenode_memory_count}"
  guest_id                   = "${var.guest_id}"
  scsi_type                  = "${data.vsphere_virtual_machine.pnda_template_base.scsi_type}"
  wait_for_guest_net_timeout = 15
  network_interface {
    network_id = "${data.vsphere_network.public.id}"
  }
  disk {
    label            = "disk0"
    size             = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.size}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 0
  }
  disk {
    label            = "disk1"
    size             = "${var.edge_node_logvolumesize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 1
  }
  disk {
    label            = "disk2"
    size             = "${var.edge_node_datamountsize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 2
  }
  clone {
    template_uuid = "${data.vsphere_virtual_machine.pnda_template_base.id}"
    /*customize {
      linux_options {
        host_name = "edge-${count.index}"
        domain    = "pnda.local"
      }
      network_interface {}
    }*/
  }
  provisioner "file" {
    source      = "./terraform/scripts"
    destination = "/tmp"
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = "ls /tmp",
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/scripts/*.sh",
      "/tmp/scripts/ssh_conf.sh",
      "/tmp/scripts/authorized_keys.sh",
      "rm -rf /tmp/scripts",
      "passwd -d root",
      "userdel -r centos"
    ],
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
}

// Tools Node
resource "vsphere_virtual_machine" "tools" {
  count                      = "${var.tools_node_count}"
  name                       = "${var.pnda_cluster_name}-tools-${count.index}"
  resource_pool_id           = "${data.vsphere_compute_cluster.cluster.resource_pool_id}"
  datastore_id               = "${data.vsphere_datastore.datastore.id}"
  folder                     = "${var.vsphere_folder}"
  num_cpus                   = "${var.toolsnode_cpu_count}"
  memory                     = "${var.toolsnode_memory_count}"
  guest_id                   = "${var.guest_id}"
  scsi_type                  = "${data.vsphere_virtual_machine.pnda_template_base.scsi_type}"
  wait_for_guest_net_timeout = 15
  network_interface {
    network_id = "${data.vsphere_network.public.id}"
  }
  disk {
    label            = "disk0"
    size             = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.size}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 0
  }
  disk {
    label            = "disk1"
    size             = "${var.tools_node_logvolumesize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 1
  }
  disk {
    label            = "disk2"
    size             = "${var.tools_node_datamountsize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 2
  }
  clone {
    template_uuid = "${data.vsphere_virtual_machine.pnda_template_base.id}"
    /*customize {
      linux_options {
        host_name = "tools-${count.index}"
        domain    = "pnda.local"
      }
      network_interface {}
    }*/
  }
  provisioner "file" {
    source      = "./terraform/scripts"
    destination = "/tmp"
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = "ls /tmp",
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/scripts/*.sh",
      "/tmp/scripts/ssh_conf.sh",
      "/tmp/scripts/authorized_keys.sh",
      "rm -rf /tmp/scripts",
      "passwd -d root",
      "userdel -r centos"
    ],
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
}

// Saltmaster Node
resource "vsphere_virtual_machine" "saltmaster" {
  count                      = "${var.saltmaster_node_count}"
  name                       = "${var.pnda_cluster_name}-saltmaster-${count.index}"
  resource_pool_id           = "${data.vsphere_compute_cluster.cluster.resource_pool_id}"
  datastore_id               = "${data.vsphere_datastore.datastore.id}"
  folder                     = "${var.vsphere_folder}"
  num_cpus                   = "${var.saltmasternode_cpu_count}"
  memory                     = "${var.saltmasternode_memory_count}"
  guest_id                   = "${var.guest_id}"
  scsi_type                  = "${data.vsphere_virtual_machine.pnda_template_base.scsi_type}"
  wait_for_guest_net_timeout = 15
  network_interface {
    network_id = "${data.vsphere_network.public.id}"
  }
  disk {
    label            = "disk0"
    size             = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.size}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 0
  }
  disk {
    label            = "disk1"
    size             = "${var.saltmaster_node_logvolumesize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 1
  }
  disk {
    label            = "disk2"
    size             = "${var.saltmaster_node_datamountsize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 2
  }
  clone {
    template_uuid = "${data.vsphere_virtual_machine.pnda_template_base.id}"
    /*customize {
      linux_options {
        host_name = "saltmaster-${count.index}"
        domain    = "pnda.local"
      }
      network_interface {}
    }*/
  }
  provisioner "file" {
    source      = "./terraform/scripts"
    destination = "/tmp"
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = "ls /tmp",
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/scripts/*.sh",
      "/tmp/scripts/ssh_conf.sh",
      "/tmp/scripts/authorized_keys.sh",
      "rm -rf /tmp/scripts",
      "passwd -d root",
      "userdel -r centos"
    ],
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
}

// jupyter Node
resource "vsphere_virtual_machine" "jupyter" {
  count                      = "${var.jupyter_node_count}"
  name                       = "${var.pnda_cluster_name}-jupyter-${count.index}"
  resource_pool_id           = "${data.vsphere_compute_cluster.cluster.resource_pool_id}"
  datastore_id               = "${data.vsphere_datastore.datastore.id}"
  folder                     = "${var.vsphere_folder}"
  num_cpus                   = "${var.jupyternode_cpu_count}"
  memory                     = "${var.jupyternode_memory_count}"
  guest_id                   = "${var.guest_id}"
  scsi_type                  = "${data.vsphere_virtual_machine.pnda_template_base.scsi_type}"
  wait_for_guest_net_timeout = 15
  network_interface {
    network_id = "${data.vsphere_network.public.id}"
  }
  disk {
    label            = "disk0"
    size             = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.size}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 0
  }
  disk {
    label            = "disk1"
    size             = "${var.jupyter_node_logvolumesize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 1
  }
  disk {
    label            = "disk2"
    size             = "${var.jupyter_node_datamountsize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 2
  }
  clone {
    template_uuid = "${data.vsphere_virtual_machine.pnda_template_base.id}"
    /*customize {
      linux_options {
        host_name = "jupyter-${count.index}"
        domain    = "pnda.local"
      }
      network_interface {}
    }*/
  }
  provisioner "file" {
    source      = "./terraform/scripts"
    destination = "/tmp"
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = "ls /tmp",
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/scripts/*.sh",
      "/tmp/scripts/ssh_conf.sh",
      "/tmp/scripts/authorized_keys.sh",
      "rm -rf /tmp/scripts",
      "passwd -d root",
      "userdel -r centos"
    ],
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
}

// gateway Node
resource "vsphere_virtual_machine" "gateway" {
  count                      = "${var.gateway_node_count}"
  name                       = "${var.pnda_cluster_name}-gateway-${count.index}"
  resource_pool_id           = "${data.vsphere_compute_cluster.cluster.resource_pool_id}"
  datastore_id               = "${data.vsphere_datastore.datastore.id}"
  folder                     = "${var.vsphere_folder}"
  num_cpus                   = "${var.gatewaynode_cpu_count}"
  memory                     = "${var.gatewaynode_memory_count}"
  guest_id                   = "${var.guest_id}"
  scsi_type                  = "${data.vsphere_virtual_machine.pnda_template_base.scsi_type}"
  wait_for_guest_net_timeout = 15
  network_interface {
    network_id = "${data.vsphere_network.public.id}"
  }
  disk {
    label            = "disk0"
    size             = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.size}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 0
  }
  disk {
    label            = "disk1"
    size             = "${var.gateway_node_logvolumesize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 1
  }
  disk {
    label            = "disk2"
    size             = "${var.gateway_node_datamountsize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 2
  }
  clone {
    template_uuid = "${data.vsphere_virtual_machine.pnda_template_base.id}"
    /*customize {
      linux_options {
        host_name = "gateway-${count.index}"
        domain    = "pnda.local"
      }
      network_interface {}
    }*/
  }
  provisioner "file" {
    source      = "./terraform/scripts"
    destination = "/tmp"
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = "ls /tmp",
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/scripts/*.sh",
      "/tmp/scripts/ssh_conf.sh",
      "/tmp/scripts/authorized_keys.sh",
      "rm -rf /tmp/scripts",
      "passwd -d root",
      "userdel -r centos"
    ],
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
}

// logserver Node
resource "vsphere_virtual_machine" "logserver" {
  count                      = "${var.logserver_node_count}"
  name                       = "${var.pnda_cluster_name}-logserver-${count.index}"
  resource_pool_id           = "${data.vsphere_compute_cluster.cluster.resource_pool_id}"
  datastore_id               = "${data.vsphere_datastore.datastore.id}"
  folder                     = "${var.vsphere_folder}"
  num_cpus                   = "${var.logservernode_cpu_count}"
  memory                     = "${var.logservernode_memory_count}"
  guest_id                   = "${var.guest_id}"
  scsi_type                  = "${data.vsphere_virtual_machine.pnda_template_base.scsi_type}"
  wait_for_guest_net_timeout = 15
  network_interface {
    network_id = "${data.vsphere_network.public.id}"
  }
  disk {
    label            = "disk0"
    size             = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.size}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 0
  }
  disk {
    label            = "disk1"
    size             = "${var.logserver_node_logvolumesize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 1
  }
  disk {
    label            = "disk2"
    size             = "${var.logserver_node_datamountsize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 2
  }
  clone {
    template_uuid = "${data.vsphere_virtual_machine.pnda_template_base.id}"
    /*customize {
      linux_options {
        host_name = "logserver-${count.index}"
        domain    = "pnda.local"
      }
      network_interface {}
    }*/
  }
  provisioner "file" {
    source      = "./terraform/scripts"
    destination = "/tmp"
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = "ls /tmp",
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/scripts/*.sh",
      "/tmp/scripts/ssh_conf.sh",
      "/tmp/scripts/authorized_keys.sh",
      "rm -rf /tmp/scripts",
      "passwd -d root",
      "userdel -r centos"
    ],
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
}

// OpenTSDB Node
resource "vsphere_virtual_machine" "opentsdb" {
  count                      = "${var.opentsdb_node_count}"
  name                       = "${var.pnda_cluster_name}-opentsdb-${count.index}"
  resource_pool_id           = "${data.vsphere_compute_cluster.cluster.resource_pool_id}"
  datastore_id               = "${data.vsphere_datastore.datastore.id}"
  folder                     = "${var.vsphere_folder}"
  num_cpus                   = "${var.opentsdbnode_cpu_count}"
  memory                     = "${var.opentsdbnode_memory_count}"
  guest_id                   = "${var.guest_id}"
  scsi_type                  = "${data.vsphere_virtual_machine.pnda_template_base.scsi_type}"
  wait_for_guest_net_timeout = 15
  network_interface {
    network_id = "${data.vsphere_network.public.id}"
  }
  disk {
    label            = "disk0"
    size             = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.size}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 0
  }
  disk {
    label            = "disk1"
    size             = "${var.opentsdb_node_logvolumesize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 1
  }
  disk {
    label            = "disk2"
    size             = "${var.opentsdb_node_datamountsize}"
    thin_provisioned = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.thin_provisioned}"
    eagerly_scrub    = "${data.vsphere_virtual_machine.pnda_template_base.disks.0.eagerly_scrub}"
    unit_number      = 2
  }
  clone {
    template_uuid = "${data.vsphere_virtual_machine.pnda_template_base.id}"
    /*customize {
      linux_options {
        host_name = "opentsdb-${count.index}"
        domain    = "pnda.local"
      }
      network_interface {}
    }*/
  }
  provisioner "file" {
    source      = "./terraform/scripts"
    destination = "/tmp"
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = "ls /tmp",
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/scripts/*.sh",
      "/tmp/scripts/ssh_conf.sh",
      "/tmp/scripts/authorized_keys.sh",
      "rm -rf /tmp/scripts",
      "passwd -d root",
      "userdel -r centos"
    ],
    connection {
      type     = "ssh"
      user     = "${var.root_user}"
      password = "${var.root_password}"
    }
  }
}
