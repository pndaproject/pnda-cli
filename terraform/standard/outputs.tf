output "hadoop-dn_private_ip" {
   value = "${ vsphere_virtual_machine.datanode.*.default_ip_address }"
}

output "kafka_private_ip" {
   value = "${ vsphere_virtual_machine.kafka.*.default_ip_address }"
}

output "hadoop-mgr_private_ip" {
   value = "${ vsphere_virtual_machine.management.*.default_ip_address }"
}

output "hadoop-cm_private_ip" {
   value = "${ vsphere_virtual_machine.cm.*.default_ip_address }"
}

output "zk_private_ip" {
   value = "${ vsphere_virtual_machine.zookeeper.*.default_ip_address }"
}

output "opentsdb_private_ip" {
   value = "${ vsphere_virtual_machine.opentsdb.*.default_ip_address }"
}

output "hadoop-edge_private_ip" {
   value = "${ vsphere_virtual_machine.edge.*.default_ip_address }"
}

output "tools_private_ip" {
   value = "${ vsphere_virtual_machine.tools.*.default_ip_address }"
}

output "saltmaster_private_ip" {
   value = "${ vsphere_virtual_machine.saltmaster.*.default_ip_address }"
}

output "gateway_private_ip" {
   value = "${ vsphere_virtual_machine.gateway.*.default_ip_address }"
}

output "jupyter_private_ip" {
   value = "${ vsphere_virtual_machine.jupyter.*.default_ip_address }"
}

output "logserver_private_ip" {
   value = "${ vsphere_virtual_machine.logserver.*.default_ip_address }"
}
