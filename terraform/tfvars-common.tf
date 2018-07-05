// Options common to all flavors of PNDA_CLUSTER
// Typically these are set via pnda_env.yaml to provide single point of configuration and used here with ${} syntax

variable "vsphere_user" {
  type = "string"
  default = "${VS_USER}"
  description = "vSphere User"
}
variable "vsphere_password" {
  type = "string"
  default = "${VS_PASSWORD}"
  description = "vSphere password"
}
variable cluster_name {
  type = "string"
  default = "${VS_PARENT_CLUSTER}"
}
variable pnda_cluster_name {
  type = "string"
  default = "${PNDA_CLUSTER}"
}
variable "datacenter"{
  default = "${VS_DATACENTER}"
}
variable DS {
  type = "string"
  default = "${VS_DS}"
  description = "Datastore"
}
variable thin_provision {
  default = "true"
}
variable public_network {
  type = "string"
  default = "${VS_PUBLIC_NETWORK}"
}
variable "vsphere_server" {
  type = "string"
  default = "${VS_SERVER}"
}
variable "vsphere_folder" {
  type = "string"
  default = "${VS_FOLDER}"
}
variable guest_id {
  type = "string"
  default = "${VS_GUEST_ID}"
}
variable pnda_template_base {
  type = "string"
  default = "${VS_TEMPLATE_BASE}"
}
variable pnda_template_datanode {
  type = "string"
  default = "${VS_TEMPLATE_DATANODE}"
}
variable pnda_template_kafka {
  type = "string"
  default = "${VS_TEMPLATE_KAFKA}"
}
variable root_user {
  type = "string"
  default = "${TF_ROOT_USER}"
}
variable root_password {
  type = "string"
  default = "${TF_ROOT_PASSWORD}"
}