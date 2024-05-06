Creating Kubernetes clusters on AWS EC2 with Terraform and Ansible
==================================================================

Table of contents
-----------------

- [Table of contents](#table-of-contents)
- [Steps for running Terraform](#steps-for-running-terraform)
- [Steps for running Ansible](#steps-for-running-ansible)
- [Terraform Script (main.tf)](#terraform-script-maintf)
- [Ansible Playbook Scripts](#ansible-playbook-scripts)
- [Run the Ansible Playbook](#run-the-ansible-playbook)
- [Verify that the K8s cluster works](#verify-that-the-k8s-cluster-works)

Steps for running Terraform
---------------------------

1. Installing Terraform:

    To install Terraform, first download the appropriate binary for your operating system from the Terraform official website.

    Once downloaded, unzip the archive and either add the binary to your PATH or copy it to a location of your choice.

2. Setting up AWS Authentication:

    You need AWS credentials to manage AWS resources. You can either set environment variables to provide authentication information or store credentials in the ~/.aws/credentials file.

3. Initializing Terraform Configuration:

    To initialize Terraform configuration, navigate to the directory containing your Terraform files in your terminal and run the following command:

    ```
    terraform init
    ```

    This command initializes the Terraform configuration in the current directory and downloads any necessary plugins.

4. Executing Terraform Scripts:
    Once the configuration is initialized, you can execute your Terraform scripts to provision and manage AWS resources.

    Run the following command to execute the Terraform script:

    ```
    terraform apply
    ```

    After running the command, review the changes and approve them. Terraform will then create and manage the defined resources on AWS.

Steps for running Ansible
-------------------------

1. Installing Ansible:

    Ansible is typically installed using package managers. On Linux, you can install Ansible using package managers provided by most distributions.

    For example, on Ubuntu or Debian, you can install Ansible with the following commands:

    ```
    sudo apt-get update
    sudo apt-get install ansible
    ```

2. Setting up Inventory:

    Ansible requires an inventory file that contains the hosts and groups it will manage. By default, Ansible uses the /etc/ansible/hosts file as the inventory.

    You can create an inventory file manually and add hosts to it.

3. Setting up SSH Access:

    To connect to hosts using Ansible, SSH access is required.

    Configure SSH keys for hosts and ensure that Ansible can use those keys by configuring the ~/.ssh/config file.

4. Executing Ansible Playbooks:
    Run Ansible Playbooks to manage configurations. Use the ansible-playbook command to execute them.

    Execute the playbook with the following command:

    ```
    ansible-playbook -i inventory.ini deploy_kubernetes.yml
    ```

    This command specifies the inventory file (inventory.ini) and the playbook to execute (deploy_kubernetes.yml).

    When the playbook runs, the defined tasks will be executed on the specified hosts.

Terraform Script (main.tf)
--------------------------

main.tf

```jsonc
# Set Terraform provider
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "5.4.0"
    }
    tls = {
      source = "hashicorp/tls"
      version = "4.0.4"
    }
    ansible = {
      source = "ansible/ansible"
      version = "1.1.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Create the VPC
resource "aws_vpc" "kubeadm_vpc" {

  cidr_block = var.vpc_cidr_block
  enable_dns_hostnames = true

  tags = {
    # NOTE: very important to use an uppercase N to set the name in the console
    Name = "kubeadm_vpc"
    "kubernetes.io/cluster/kubernetes" = "owned"
  }
}

# Create a public subnet
resource "aws_subnet" "kubeadm_subnet" {
  vpc_id = aws_vpc.kubeadm_vpc.id
  cidr_block = "10.0.1.0/24"
  map_public_ip_on_launch = true

  tags = {
    Name = "kubeadm_public_subnet"
  }
}

# Create an internet gateway and attach it to the VPC
resource "aws_internet_gateway" "kubeadm_igw" {
  vpc_id = aws_vpc.kubeadm_vpc.id

  tags = {
    Name = "Kubeadm Internet GW"
  }
}

# Create a route table (0.0.0.0/0 to -> IGW) and attach it to the subnet
resource "aws_route_table" "kubeadm_routetable" {
  vpc_id = aws_vpc.kubeadm_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.kubeadm_igw.id
  }

  tags = {
    Name = "kubeadm IGW route table"
  }
}

resource "aws_route_table_association" "kubeadm_route_association" {
  subnet_id = aws_subnet.kubeadm_subnet.id
  route_table_id = aws_route_table.kubeadm_routetable.id
}

# Create a security group to open the required ports - K8s control Plane
resource "aws_security_group" "kubeadm_sg_control_plane" {
  name = "kubeadm-control-plane security group"
  ingress {
    description = "API Server"
    protocol = "tcp"
    from_port = 6443
    to_port = 6443
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Kubelet API"
    protocol = "tcp"
    from_port = 2379
    to_port = 2380
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "etcd server client API"
    protocol = "tcp"
    from_port = 10250
    to_port = 10250
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Kube Scheduler"
    protocol = "tcp"
    from_port = 10259
    to_port = 10259
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Kube Contoller Manager"
    protocol = "tcp"
    from_port = 10257
    to_port = 10257
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Control Plane SG"
  }
}

# Create a security group to open the required ports - K8s worker nodes
resource "aws_security_group" "kubeadm_sg_worker_nodes" {
  name = "kubeadm-worker-node security group"

  ingress {
    description = "kubelet API"
    protocol = "tcp"
    from_port = 10250
    to_port = 10250
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "NodePort services"
    protocol = "tcp"
    from_port = 30000
    to_port = 32767
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Worker Nodes SG"
  }
}

# Create the security groups for http(s) and ssh
resource "aws_security_group" "kubeadm_sg_common" {
  name = "common-ports"
  tags = {
    Name = "common ports"
  }

  ingress {
    description = "Allow SSH"
    protocol = "tcp"
    from_port = 22
    to_port = 22
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow HTTP"
    protocol = "tcp"
    from_port = 80
    to_port = 80
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow HTTPS"
    protocol = "tcp"
    from_port = 443
    to_port = 443
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Create a security group for flannel
resource "aws_security_group" "kubeadm_sg_flannel" {
  name = "flannel-overlay-backend"
  tags = {
    Name = "Flannel Overlay backend"
  }

  ingress {
    description = "flannel overlay backend"
    protocol = "udp"
    from_port = 8285
    to_port = 8285
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "flannel vxlan backend"
    protocol = "udp"
    from_port = 8472
    to_port =  8472
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Create three nodes inside the subnet and attach the security group
#   Create a private key
resource "tls_private_key" "kubeadm_private_key" {

  algorithm = "RSA"
  rsa_bits  = 4096

  provisioner "local-exec" { # Create a "pubkey.pem" to your computer!!
    command = "echo '${self.public_key_pem}' > ./pubkey.pem"
  }
}

#   Create a key pair and output the private key locally
resource "aws_key_pair" "kubeadm_key_pair" {
  key_name = var.keypair_name
  public_key = tls_private_key.kubeadm_private_key.public_key_openssh

  provisioner "local-exec" { # Create a "myKey.pem" to your computer!!
    command = "echo '${tls_private_key.kubeadm_private_key.private_key_pem}' > ./private-key.pem"
  }
}

# Create the control plane node
resource "aws_instance" "kubeadm_control_plane" {
  ami = var.ubuntu_ami
  instance_type = "t2.medium"
  key_name = aws_key_pair.kubeadm_key_pair.key_name
  associate_public_ip_address = true
  security_groups = [
    aws_security_group.kubeadm_sg_common.name,
    aws_security_group.kubeadm_sg_flannel.name,
    aws_security_group.kubeadm_sg_control_plane.name,
  ]
  root_block_device {
    volume_type = "gp2"
    volume_size = 14
  }

  tags = {
    Name = "Kubeadm Master"
    Role = "Control plane node"
  }

  provisioner "local-exec" {
    command = "echo 'master ${self.public_ip}' >> ./hosts"
  }
}

# Create the worker nodes
resource "aws_instance" "kubeadm_worker_nodes" {
  count = var.worker_nodes_count
  ami = var.ubuntu_ami
  instance_type = "t2.micro"
  key_name = aws_key_pair.kubeadm_key_pair.key_name
  associate_public_ip_address = true
  security_groups = [
    aws_security_group.kubeadm_sg_flannel.name,
    aws_security_group.kubeadm_sg_common.name,
    aws_security_group.kubeadm_sg_worker_nodes.name,
  ]
  root_block_device {
    volume_type = "gp2"
    volume_size = 8
  }

  tags = {
    Name = "Kubeadm Worker ${count.index}"
    Role = "Worker node"
  }

  provisioner "local-exec" {
    command = "echo 'worker-${count.index} ${self.public_ip}' >> ./hosts"
  }
}

# Create the ansible hosts
resource "ansible_host" "kubeadm_control_plane_host" {
  depends_on = [
    aws_instance.kubeadm_control_plane
  ]
  name = "control_plane"
  groups = ["master"]
  variables = {
    ansible_user = "ubuntu"
    ansible_host = aws_instance.kubeadm_control_plane.public_ip
    ansible_ssh_private_key_file = "./private-key.pem"
    node_hostname = "master"
  }
}

resource "ansible_host" "kubeadm_worker_nodes_host" {
  depends_on = [
    aws_instance.kubeadm_worker_nodes
  ]
  count = 2
  name = "worker-${count.index}"
  groups = ["workers"]
  variables = {
    node_hostname = "worker-${count.index}"
    ansible_user = "ubuntu"
    ansible_host = aws_instance.kubeadm_worker_nodes[count.index].public_ip
    ansible_ssh_private_key_file = "./private-key.pem"
  }
}
```

Ansible Playbook Scripts
------------------------

inventory.yml

```yml
---
plugin: cloud.terraform.terraform_provider
```

playbook.yml

```yml
# playbook.yml

- name: Basic Setup
  hosts: all
  gather_facts: false
  become: true
  tasks:
    - name: Wait 200 seconds for port 22 to become open and contain "OpenSSH"
      ansible.builtin.wait_for:
        port: 22
        host: "{{ (ansible_ssh_host|default(ansible_host))|default(inventory_hostname) }}"
        search_regex: OpenSSH
        delay: 10
        timeout: 200
      vars:
        ansible_connection: local

    - name: Set a hostname
      ansible.builtin.hostname:
        name: "{{ node_hostname }}"

    - name: Copy /etc/hosts template
      ansible.builtin.copy:
        backup: true
        src: ./hosts
        dest: /tmp/hosts

    - name: Insert/Update configuration using a local file and validate it
      ansible.builtin.blockinfile:
        block: "{{ lookup('file', './hosts') }}"
        path: /etc/hosts
        backup: yes

    - name: Disable swap on all nodes
      ansible.builtin.shell: swapoff -a

    - name: kernel module prerequesites
      ansible.builtin.shell:
        cmd: |
          cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
          overlay
          br_netfilter
          EOF

    - name: add overlay module
      community.general.modprobe:
        name: overlay
        state: present

    - name: add br_netfilter module
      community.general.modprobe:
        name: br_netfilter
        state: present

    - name: sysctl params required by setup
      ansible.builtin.shell:
        cmd: |
          cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
          net.bridge.bridge-nf-call-iptables  = 1
          net.bridge.bridge-nf-call-ip6tables = 1
          net.ipv4.ip_forward                 = 1
          EOF

    - name: apply sysctl params without reboot
      ansible.builtin.shell: sysctl --system

    - name: create containerd config file
      ansible.builtin.shell: mkdir -p /etc/containerd && touch /etc/containerd/config.toml

    - name: Install containerd pre-reqs
      ansible.builtin.apt:
        pkg:
          - apt-transport-https
          - ca-certificates
          - curl
          - gnupg
          - lsb-release

    - name: add docker GPG key
      apt_key:
        url: https://download.docker.com/linux/ubuntu/gpg
        state: present

    - name: Add Docker Repository
      apt_repository:
        repo: deb https://download.docker.com/linux/ubuntu jammy stable
        state: present

    - name: Update apt and install docker-ce
      apt:
        name: docker-ce
        state: latest
        update_cache: true

    - name: Install containerd.io
      ansible.builtin.apt:
        pkg:
          - containerd.io

    - name: Enable containerd
      ansible.builtin.systemd:
        name: containerd
        daemon_reload: yes
        state: started
        enabled: yes

    - name: Setup containerd to use systemd as cgroup
      ansible.builtin.copy:
        backup: true
        src: ./containerd-config.toml
        dest: /etc/containerd/config.toml

    - name: Restart service cron, in all cases, also issue daemon-reload to pick up config changes
      ansible.builtin.systemd:
        state: restarted
        daemon_reload: yes
        name: containerd

    ## NOTE: kubeadm stuff
    - name: Download Google Cloud's public key
      ansible.builtin.apt_key:
        url: https://packages.cloud.google.com/apt/doc/apt-key.gpg
        state: present

    - name: Add kubernetes repo
      ansible.builtin.apt_repository:
        repo: deb https://apt.kubernetes.io/ kubernetes-xenial main
        state: present
        filename: kubernetes

    - name: Install kubeadm, kubectl, kubelet
      ansible.builtin.apt:
        pkg:
          - kubelet
          - kubeadm
          - kubectl

    - name: hold kubectl,kubeadm,kubelet packages
      ansible.builtin.shell: apt-mark hold kubelet kubectl kubeadm

- name: Setup Control Plane Node
  hosts: master
  become: true
  tasks:
    - name: init kubeadm
      ansible.builtin.shell: sudo kubeadm init --pod-network-cidr=10.244.0.0/16 --control-plane-endpoint "{{ansible_host}}:6443"

    - name: create ~/.kube directory
      ansible.builtin.file:
        path: ~/.kube
        state: directory
        mode: "0755"

    - name: copy kubeconfig file
      shell: sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config

    - name: set the correct permission on kubeconfig file
      shell: sudo chown $(id -u):$(id -g) $HOME/.kube/config

    - name: install flannel
      ansible.builtin.shell: kubectl apply -f https://raw.githubusercontent.com/flannel-io/flannel/v0.20.2/Documentation/kube-flannel.yml

    - name: Copy kubeconfig file locally
      ansible.builtin.fetch:
        src: $HOME/.kube/config
        dest: /tmp/kubeconfig/
        flat: yes

    - name: Generate join token for worker nodes
      ansible.builtin.shell: sudo kubeadm token create --print-join-command
      register: join_node_token

    - name: Save join command as variable
      ansible.builtin.set_fact:
        join_node: "{{ join_node_token.stdout_lines[0] }}"

- name: Setup Worker Nodes
  hosts: workers
  become: true
  tasks:
    - name: add worker nodes to cluster
      shell: "sudo {{ hostvars['control_plane'].join_node }}"
```

containerd-config.toml (Called from playbook.yml. Setup containerd to use systemd as cgroup, Called from playbook.yml)

```dosini
# containerd-config.toml

disabled_plugins = []
imports = []
oom_score = 0
plugin_dir = ""
required_plugins = []
root = "/var/lib/containerd"
state = "/run/containerd"
version = 2

[cgroup]
  path = ""

[debug]
  address = ""
  format = ""
  gid = 0
  level = ""
  uid = 0

[grpc]
  address = "/run/containerd/containerd.sock"
  gid = 0
  max_recv_message_size = 16777216
  max_send_message_size = 16777216
  tcp_address = ""
  tcp_tls_cert = ""
  tcp_tls_key = ""
  uid = 0

[metrics]
  address = ""
  grpc_histogram = false

[plugins]

  [plugins."io.containerd.gc.v1.scheduler"]
    deletion_threshold = 0
    mutation_threshold = 100
    pause_threshold = 0.02
    schedule_delay = "0s"
    startup_delay = "100ms"

  [plugins."io.containerd.grpc.v1.cri"]
    disable_apparmor = false
    disable_cgroup = false
    disable_hugetlb_controller = true
    disable_proc_mount = false
    disable_tcp_service = true
    enable_selinux = false
    enable_tls_streaming = false
    ignore_image_defined_volumes = false
    max_concurrent_downloads = 3
    max_container_log_line_size = 16384
    netns_mounts_under_state_dir = false
    restrict_oom_score_adj = false
    sandbox_image = "k8s.gcr.io/pause:3.5"
    selinux_category_range = 1024
    stats_collect_period = 10
    stream_idle_timeout = "4h0m0s"
    stream_server_address = "127.0.0.1"
    stream_server_port = "0"
    systemd_cgroup = false
    tolerate_missing_hugetlb_controller = true
    unset_seccomp_profile = ""

    [plugins."io.containerd.grpc.v1.cri".cni]
      bin_dir = "/opt/cni/bin"
      conf_dir = "/etc/cni/net.d"
      conf_template = ""
      max_conf_num = 1

    [plugins."io.containerd.grpc.v1.cri".containerd]
      default_runtime_name = "runc"
      disable_snapshot_annotations = true
      discard_unpacked_layers = false
      no_pivot = false
      snapshotter = "overlayfs"

      [plugins."io.containerd.grpc.v1.cri".containerd.default_runtime]
        base_runtime_spec = ""
        container_annotations = []
        pod_annotations = []
        privileged_without_host_devices = false
        runtime_engine = ""
        runtime_root = ""
        runtime_type = ""

        [plugins."io.containerd.grpc.v1.cri".containerd.default_runtime.options]

      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes]

        [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
          base_runtime_spec = ""
          container_annotations = []
          pod_annotations = []
          privileged_without_host_devices = false
          runtime_engine = ""
          runtime_root = ""
          runtime_type = "io.containerd.runc.v2"

          [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
            BinaryName = ""
            CriuImagePath = ""
            CriuPath = ""
            CriuWorkPath = ""
            IoGid = 0
            IoUid = 0
            NoNewKeyring = false
            NoPivotRoot = false
            Root = ""
            ShimCgroup = ""
            SystemdCgroup = true

      [plugins."io.containerd.grpc.v1.cri".containerd.untrusted_workload_runtime]
        base_runtime_spec = ""
        container_annotations = []
        pod_annotations = []
        privileged_without_host_devices = false
        runtime_engine = ""
        runtime_root = ""
        runtime_type = ""

        [plugins."io.containerd.grpc.v1.cri".containerd.untrusted_workload_runtime.options]

    [plugins."io.containerd.grpc.v1.cri".image_decryption]
      key_model = "node"

    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = ""

      [plugins."io.containerd.grpc.v1.cri".registry.auths]

      [plugins."io.containerd.grpc.v1.cri".registry.configs]

      [plugins."io.containerd.grpc.v1.cri".registry.headers]

      [plugins."io.containerd.grpc.v1.cri".registry.mirrors]

    [plugins."io.containerd.grpc.v1.cri".x509_key_pair_streaming]
      tls_cert_file = ""
      tls_key_file = ""

  [plugins."io.containerd.internal.v1.opt"]
    path = "/opt/containerd"

  [plugins."io.containerd.internal.v1.restart"]
    interval = "10s"

  [plugins."io.containerd.metadata.v1.bolt"]
    content_sharing_policy = "shared"

  [plugins."io.containerd.monitor.v1.cgroups"]
    no_prometheus = false

  [plugins."io.containerd.runtime.v1.linux"]
    no_shim = false
    runtime = "runc"
    runtime_root = ""
    shim = "containerd-shim"
    shim_debug = false

  [plugins."io.containerd.runtime.v2.task"]
    platforms = ["linux/amd64"]

  [plugins."io.containerd.service.v1.diff-service"]
    default = ["walking"]

  [plugins."io.containerd.snapshotter.v1.aufs"]
    root_path = ""

  [plugins."io.containerd.snapshotter.v1.btrfs"]
    root_path = ""

  [plugins."io.containerd.snapshotter.v1.devmapper"]
    async_remove = false
    base_image_size = ""
    pool_name = ""
    root_path = ""

  [plugins."io.containerd.snapshotter.v1.native"]
    root_path = ""

  [plugins."io.containerd.snapshotter.v1.overlayfs"]
    root_path = ""

  [plugins."io.containerd.snapshotter.v1.zfs"]
    root_path = ""

[proxy_plugins]

[stream_processors]

  [stream_processors."io.containerd.ocicrypt.decoder.v1.tar"]
    accepts = ["application/vnd.oci.image.layer.v1.tar+encrypted"]
    args = ["--decryption-keys-path", "/etc/containerd/ocicrypt/keys"]
    env = ["OCICRYPT_KEYPROVIDER_CONFIG=/etc/containerd/ocicrypt/ocicrypt_keyprovider.conf"]
    path = "ctd-decoder"
    returns = "application/vnd.oci.image.layer.v1.tar"

  [stream_processors."io.containerd.ocicrypt.decoder.v1.tar.gzip"]
    accepts = ["application/vnd.oci.image.layer.v1.tar+gzip+encrypted"]
    args = ["--decryption-keys-path", "/etc/containerd/ocicrypt/keys"]
    env = ["OCICRYPT_KEYPROVIDER_CONFIG=/etc/containerd/ocicrypt/ocicrypt_keyprovider.conf"]
    path = "ctd-decoder"
    returns = "application/vnd.oci.image.layer.v1.tar+gzip"

[timeouts]
  "io.containerd.timeout.shim.cleanup" = "5s"
  "io.containerd.timeout.shim.load" = "5s"
  "io.containerd.timeout.shim.shutdown" = "3s"
  "io.containerd.timeout.task.state" = "2s"

[ttrpc]
  address = ""
  gid = 0
  uid = 0
```

Run the Ansible Playbook
------------------------

```
chmod 600 myKey.pem
ansible-playbook -i inventory.yml playbook.yml
```

Verify that the K8s cluster works
---------------------------------

```
alias k=kubectl
k get nodes
k run nginx --image=nginx:alpine
k expose pod nginx --name=demo-svc --port 8000 --target-port=80
k get svc -o wide
k run temp --image=nginx:alpine --rm -it --restart=Never -- curl http://demo-svc:8000
```
