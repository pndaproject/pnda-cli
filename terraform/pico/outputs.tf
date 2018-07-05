output "hadoop-dn_private_ip" {
   value = "${ vsphere_virtual_machine.datanode.*.default_ip_address }"
}

output "kafka_private_ip" {
   value = "${ vsphere_virtual_machine.kafka.*.default_ip_address }"
}

output "hadoop-mgr_private_ip" {
   value = "${ vsphere_virtual_machine.management.*.default_ip_address }"
}

output "hadoop-edge_private_ip" {
   value = "${ vsphere_virtual_machine.edge.*.default_ip_address }"
}

output "gateway_private_ip" {
   value = "${ vsphere_virtual_machine.gateway.*.default_ip_address }"
}
