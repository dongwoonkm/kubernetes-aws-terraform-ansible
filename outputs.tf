# outputs.tf
#   $ terraform output
#   control_plane_ip = "84.137.72"
#   worker_node_ip = "18.234.50.157"
#
#   $ terraform output control_plane_ip
#   control_plane_ip = "84.137.72"

output "control_plane_ip" {
  value = aws_instance.kubeadm_control_plane.public_ip
}

output "worker_nodes_ip" {
  value = join("", aws_instance.kubeadm_worker_nodes[*].public_ip)
}
