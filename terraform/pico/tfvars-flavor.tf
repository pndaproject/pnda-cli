// Vertical scale options that vary according to the flavor of PNDA being created

// Datanode Node Variables
variable "datanode_count" {
  default = "${DATANODE_COUNT}"
}
variable "datanode_logvolumesize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the log volume"
}
variable "datanode_data1mountsize" {
  type        = "string"
  default     = "50"
  description = "Size in GB for the data1 directory mount"
}
variable "datanode_data2mountsize" {
  type        = "string"
  default     = "50"
  description = "Size in GB for the data2 directory mount"
}
variable "datanode_cpu_count" {
  default     = "8"
  description = "Number of CPUs for the Datanode"
}
variable "datanode_memory_count" {
  default     = "32000"
  description = "Amount of Memory for the Data Node(s)"
}


// Kafka Node Variables
variable "kafkanode_count" {
  default = "${KAFKA_COUNT}"
}
variable "kafka_logvolumesize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the log volume"
}
variable "kafka_datamountsize" {
  type        = "string"
  default     = "50"
  description = "Size in GB for the data directory mount"
}
variable "kafka_data2mountsize" {
  type        = "string"
  default     = "50"
  description = "Size in GB for the data directory mount"
}
variable "kafka_cpu_count" {
  default     = "4"
  description = "Number of CPUs for the Kafka Brokers"
}
variable "kafkanode_memory_count" {
  default     = "20000"
  description = "Amount of Memory for the Kafka Node(s)"
}


// Zookeeper Node Variables
variable "zookeeper_count" {
  default     = "0"
  description = "Number of zookeeper nodes"
}
variable "zookeeper_logvolumesize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the log volume"
}
variable "zookeeper_datamountsize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the data directory mount"
}
variable "zookeeper_cpu_count" {
  default     = "4"
  description = "Number of CPUs for the Zookeepers"
}
variable "zookeeper_memory_count" {
  default     = "20000"
  description = "Amount of Memory for the Zookeeper Node(s)"
}


// Hadoop Management Node Variables
variable "management_count" {
  default     = "1"
  description = "Number of management nodes"
}
variable "management_logvolumesize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the log volume"
}
variable "management_datamountsize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the data directory mount"
}
variable "management_cpu_count" {
  default     = "8"
  description = "Number of CPUs for the Management nodes"
}
variable "managementnode_memory_count" {
  default     = "32000"
  description = "Amount of Memory for the Management Node(s)"
}

// Hadoop Cluster Manager Node Variables
variable "cm_count" {
  default     = "0"
  description = "Number of cluster manager nodes"
}
variable "cm_logvolumesize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the log volume"
}
variable "cm_datamountsize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the data directory mount"
}
variable "cm_cpu_count" {
  default     = "8"
  description = "Number of CPUs for the Cluster Manager"
}
variable "cm_memory_count" {
  default     = "32000"
  description = "Amount of Memory for the Cluster Manager"
}

// Edge node Variables
variable "edge_node_count" {
  default     = "1"
  description = "Number of Edge nodes in the Cluster"
}
variable "edge_node_logvolumesize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the log volume"
}
variable "edge_node_datamountsize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the data directory mount"
}
variable "edgenode_cpu_count" {
  default     = "8"
  description = "Number of CPUs for the Edge Node(s)"
}
variable "edgenode_memory_count" {
  default     = "32000"
  description = "Amount of Memory for the Edge Node(s)"
}


// Tools Node variables
variable "tools_node_count" {
  default     = "0"
  description = "Number of tools nodes in the Cluster"
}
variable "tools_node_logvolumesize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the log volume"
}
variable "tools_node_datamountsize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the data directory mount"
}
variable "toolsnode_cpu_count" {
  default     = "8"
  description = "Number of CPUs for the Tools Node(s)"
}
variable "toolsnode_memory_count" {
  default     = "20000"
  description = "Amount of Memory for the Tools Node(s)"
}

// Saltmaster Node variables
variable "saltmaster_node_count" {
  default     = "0"
  description = "Number of saltmaster nodes in the Cluster"
}
variable "saltmaster_node_logvolumesize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the log volume"
}
variable "saltmaster_node_datamountsize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the data directory mount"
}
variable "saltmasternode_cpu_count" {
  default     = "8"
  description = "Number of CPUs for the Saltmaster Node(s)"
}
variable "saltmasternode_memory_count" {
  default     = "20000"
  description = "Amount of Memory for the Saltmaster Node(s)"
}

// Jupyter Node variables
variable "jupyter_node_count" {
  default     = "0"
  description = "Number of jupyter nodes in the Cluster"
}
variable "jupyter_node_logvolumesize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the log volume"
}
variable "jupyter_node_datamountsize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the data directory mount"
}
variable "jupyternode_cpu_count" {
  default     = "8"
  description = "Number of CPUs for the Jupyter Node(s)"
}
variable "jupyternode_memory_count" {
  default     = "20000"
  description = "Amount of Memory for the Jupyter Node(s)"
}

// gateway Node variables
variable "gateway_node_count" {
  default     = "1"
  description = "Number of Gateway nodes in the Cluster"
}
variable "gateway_node_logvolumesize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the log volume"
}
variable "gateway_node_datamountsize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the data directory mount"
}
variable "gatewaynode_cpu_count" {
  default     = "8"
  description = "Number of CPUs for the Gateway Node(s)"
}
variable "gatewaynode_memory_count" {
  default     = "20000"
  description = "Amount of Memory for the Gateway Node(s)"
}

// Logserver Node variables
variable "logserver_node_count" {
  default     = "0"
  description = "Number of logserver nodes in the Cluster"
}
variable "logserver_node_logvolumesize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the log volume"
}
variable "logserver_node_datamountsize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the data directory mount"
}
variable "logservernode_cpu_count" {
  default     = "8"
  description = "Number of CPUs for the Logserver Node(s)"
}
variable "logservernode_memory_count" {
  default     = "20000"
  description = "Amount of Memory for the Logserver Node(s)"
}
// OpenTSDB Node variables
variable "opentsdb_node_count" {
  default     = "${OPENTSDB_COUNT}"
  description = "Number of OpenTSDB nodes in the Cluster"
}
variable "opentsdb_node_logvolumesize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the log volume"
}
variable "opentsdb_node_datamountsize" {
  type        = "string"
  default     = "20"
  description = "Size in GB for the data directory mount"
}
variable "opentsdbnode_cpu_count" {
  default     = "8"
  description = "Number of CPUs for the OpenTSDB Node(s)"
}
variable "opentsdbnode_memory_count" {
  default     = "20000"
  description = "Amount of Memory for the OpenTSDB Node(s)"
}
