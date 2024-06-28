# Kong API Gateway on EKS
## Introduction
Kong API Gateway is a light weight, fast, and flexible cloud native API gateway. It is a powerful and scalable open-source platform designed to manage and secure APIs and microservices. Built on top of NGINX, it provides high performance and flexibility, making it ideal for modern, distributed architectures. Kong acts as a central point for managing API traffic, providing features like authentication, rate limiting, logging, and more, which help streamline API management and improving security. By deploying Kong API Gateway in Kubernetes, you can leverage the advantages of container orchestration and microservices architecture, ensuring your APIs are highly available, resilient, and scalable. This integration simplifies the process of managing API lifecycles, enables seamless scaling, and enhances overall system reliability.

## KONG: why is it important
Kong API Gateway stands out as an advanced solution for API management, offering a suite of features including flexible request routing, automatic service discovery, advanced load balancing, API management, real-time analytics, and monitoring. These capabilities empower organizations to efficiently handle API traffic, discover and register APIs, distribute traffic across backend services, manage APIs throughout their lifecycle, and gain valuable insights into API performance and usage. With its extensive range of plugins, Kong enables easy customization, adding functionalities like authentication, rate limiting, and transformations. Moreover, Kong's flexible deployment options cater to diverse organizational needs, whether it's on-premises, in the cloud, or as a managed service. Enhanced security features such as authentication, authorization, encryption, and rate limiting further safeguard sensitive data and mitigate potential API attacks. Kong API Gateway thus emerges as a highly effective solution for organizations seeking to establish and maintain a robust API infrastructure.

## How Kong Works:
Kong acts as a mediator between client and your services. It sits in front of your APIs and manages requests, authentication, rate limiting and more. When a client makes request, it goes through kong, which can then route the request to the appropriate service, apply security policies and other functionalities.

Kong has two main components:
1. Control Plane
2. Data Plane

Control Plane: It is responsible for managing and configuring routes such as services, and plugins. Also it is responsible for storing configuration data. The control plane ensures that the data plane enforces the configured policies and behaviours. It interacts with the database and provides an Admin API for configuration management.

Data Plane: It is responsible for processing incoming requests and routing them to the appropriate services. It acts as the gateway for incoming traffic and applies the policies and configurations set in the control plane. The data plane is where kong's core functionality, such as routing, authentication and rate limiting. It does not interact directly with the database but instead relies on the Control Plane for configuration updates.

## Pre-requisites
- EKS Cluster
- Helm
- PostgreSQL
- Terraform

## Version
`3.6.1`

## Kong EKS Architechture
![arch](https://github.com/Divya-1004/Kong/blob/main/EKS-arch.drawio.png)

## Kong Setup 

#### Helm Setup
Kong provides a Helm chart to deploy the Kong Gateway.\
Adding a repository to our machine.\
By using Terraform and Helm, we automated the deployment process.
```
helm repo add kong https://charts.konghq.com
helm repo update
```
## Helm chart version
`2.37.0`

### Why Automate Kong?
Automating the Kong API Gateway provides numerous advantages that enhance overall efficiency and effectiveness. By automating deployment and management tasks, organizations can significantly reduce the time and effort required for setup and updates. This not only simplifies the initial setup process but also ensures that any changes or scaling requirements can be implemented quickly and reliably. Consistent configurations minimize human errors, which is crucial for maintaining reliability and availability, as automated monitoring and management promptly detect and resolve issues. Additionally, automation facilitates scalability, allowing the gateway to handle increasing traffic and expanding infrastructure with ease. Security is also enhanced through the consistent application of security policies and updates. Overall, automation reduces operational costs and increases efficiency, making it a vital strategy for organizations seeking a robust and scalable API management solution.


### Steps to Spin up an EKS Cluster via Terraform 
Create a directory named `kong-EKS`.
```
mkdir kong-EKS  
cd kong-EKS
```
Within this directory, create a file named `main.tf` and add the following script to it.\
First, let's create EKS cluster.
```
provider "aws" {
  region = var.aws_region
}

# Fetch available availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# Create VPC
resource "aws_vpc" "eks_vpc" {
  cidr_block = var.vpc_cidr_block

  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "eks-vpc"
  }
}

# Create private subnets
resource "aws_subnet" "private_subnets" {
  count                   = length(var.private_subnet_cidr_blocks)
  vpc_id                  = aws_vpc.eks_vpc.id
  cidr_block              = var.private_subnet_cidr_blocks[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name                                        = "private-subnet-${count.index + 1}"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"           = 1
  }
}

# Create public subnets
resource "aws_subnet" "public_subnets" {
  count                   = length(var.public_subnet_cidr_blocks)
  vpc_id                  = aws_vpc.eks_vpc.id
  cidr_block              = var.public_subnet_cidr_blocks[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name                                        = "public-subnet-${count.index + 1}"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                    = 1
  }
}

# Create internet gateway
resource "aws_internet_gateway" "eks_igw" {
  vpc_id = aws_vpc.eks_vpc.id

  tags = {
    Name = "eks-igw"
  }
}

# Create NAT gateway
resource "aws_nat_gateway" "eks_ngw" {
  allocation_id = aws_eip.eks_eip.id
  subnet_id     = aws_subnet.public_subnets[0].id

  tags = {
    Name = "eks-ngw"
  }
}

# Create Elastic IP for NAT gateway
resource "aws_eip" "eks_eip" {
  domain = "vpc"

  tags = {
    Name = "eks-eip"
  }
}

# Create route tables for private and public subnets
resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.eks_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.eks_ngw.id
  }

  tags = {
    Name = "private-rt"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.eks_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.eks_igw.id
  }

  tags = {
    Name = "public-rt"
  }
}

# Associate route tables with subnets
resource "aws_route_table_association" "private_rt_assoc" {
  count          = length(var.private_subnet_cidr_blocks)
  subnet_id      = aws_subnet.private_subnets[count.index].id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "public_rt_assoc" {
  count          = length(var.public_subnet_cidr_blocks)
  subnet_id      = aws_subnet.public_subnets[count.index].id
  route_table_id = aws_route_table.public_rt.id
}

# Create IAM role for EKS cluster
resource "aws_iam_role" "eks_cluster_role" {
  name = "eks-cluster-role"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

# Attach required policies to the EKS cluster role
resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

resource "aws_iam_role_policy_attachment" "eks_service_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

##00
# Create an IAM role for the EKS node group
resource "aws_iam_role" "node_group_role" {
  name = "eks-node-group-role"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

# Attach the required policies to the node group role
resource "aws_iam_role_policy_attachment" "node_group_policy_attachment" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node_group_role.name
}

resource "aws_iam_role_policy_attachment" "node_group_cni_policy_attachment" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node_group_role.name
}

resource "aws_iam_role_policy_attachment" "node_group_ecr_policy_attachment" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node_group_role.name
}

# Create EKS cluster
resource "aws_eks_cluster" "eks_cluster" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster_role.arn

  vpc_config {
    subnet_ids              = aws_subnet.private_subnets[*].id
    security_group_ids      = [aws_security_group.eks_cluster_sg.id]
    endpoint_private_access = true
    endpoint_public_access  = true
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_service_policy,
  ]
}

# Create security group for EKS cluster
resource "aws_security_group" "eks_cluster_sg" {
  name        = "eks-cluster-sg"
  description = "Security group for EKS cluster"
  vpc_id      = aws_vpc.eks_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "eks-cluster-sg"
  }
}

resource "aws_launch_template" "eks_nodes1" {
  name_prefix   = "eks-nodes1-"
  instance_type = "m6i.2xlarge"

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size = 50
      volume_type = "gp3"
    }
  }
}

resource "aws_eks_node_group" "node_group1" {
  cluster_name    = aws_eks_cluster.eks_cluster.name
  node_group_name = "node-group-2"
  node_role_arn   = aws_iam_role.node_group_role.arn
  subnet_ids      = tolist(aws_subnet.private_subnets[*].id)

  scaling_config {
    desired_size = 1
    max_size     = 2
    min_size     = 1
  }

  launch_template {
    id      = aws_launch_template.eks_nodes1.id
    version = aws_launch_template.eks_nodes1.latest_version
  }

  depends_on = [
    aws_iam_role_policy_attachment.node_group_policy_attachment,
    aws_iam_role_policy_attachment.node_group_cni_policy_attachment,
    aws_iam_role_policy_attachment.node_group_ecr_policy_attachment,
  ]
}

data "aws_route53_zone" "main_zone" {
  name = "demo.cequence.ai."
}

resource "aws_route53_record" "wildcard_subdomain" {
  zone_id = data.aws_route53_zone.main_zone.zone_id
  name    = "*.kongtest.demo.cequence.ai"
  type    = "CNAME"
  ttl     = 300

  records = [data.kubernetes_service.kong-proxy.status.0.load_balancer.0.ingress.0.hostname]
}

resource "null_resource" "kubectl" {
  provisioner "local-exec" {
    command = "aws eks --region ${var.aws_region} update-kubeconfig --name ${var.cluster_name} --kubeconfig ./kubeconfig"
  }
  depends_on = [
    aws_eks_cluster.eks_cluster,
    aws_eks_node_group.node_group1,
  ]
}

data "aws_caller_identity" "current" {}

resource "helm_release" "aws_csi" {
  name             = "aws-ebs-csi-driver"
  repository       = "https://kubernetes-sigs.github.io/aws-ebs-csi-driver"
  chart            = "aws-ebs-csi-driver"
  create_namespace = false
  namespace        = "kube-system"
  values = [templatefile("csi_values.yaml", {
    account_id = data.aws_caller_identity.current.account_id
  })]
  depends_on = [
    null_resource.kubectl,
  ]
}
```
#### Configure your terminal to communicate with your cluster
Create a `aws.sh` file.
```
export AWS_ACCESS_KEY_ID="YOUR-ACCESS-KEY"
export AWS_SECRET_ACCESS_KEY="YOUR-SECRET-ACCESS-KEY"
export AWS_REGION="YOUR-REGION"
```

Create a `kubeconfig` file in the present directory.
```
aws eks --region "region-name" update-kubeconfig --name "cluster-name" --kubeconfig ./kubeconfig
export KUBECONFIG=kubeconfig
```
Create a file named `variables.tf`, to declare all the variables and add the following script.
```
variable "aws_region" {
  description = "AWS region to create resources in"
}

variable "vpc_cidr_block" {
  description = "CIDR block for the VPC"
}

variable "private_subnet_cidr_blocks" {
  description = "CIDR blocks for the private subnets"
}

variable "public_subnet_cidr_blocks" {
  description = "CIDR blocks for the public subnets"
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
}

```
Next create a file named `terraform.tfvars`, to define all the values of the variables, and add below content in it.
```
aws_region                 = "YOUR-REGION"
vpc_cidr_block             = "10.100.0.0/16"
private_subnet_cidr_blocks = ["10.100.1.0/24", "10.100.2.0/24"]
public_subnet_cidr_blocks  = ["10.100.3.0/24", "10.100.4.0/24"]
cluster_name               = "CLUSTER-NAME"

## Kong Related Variables
kube_config_path = "./kubeconfig"
chart_version    = "2.37.0"
namespace        = "nskong"
helm_repository  = "https://charts.konghq.com"
helm_chart       = "kong"
database         = "postgres"
pg_database      = "kong"
pg_user          = "kong"
pg_password      = "demo123"
```
Then create a file named `output.tf` and add the following script.
```
output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = aws_eks_cluster.eks_cluster.endpoint
}

output "cluster_name" {
  description = "Name of the EKS cluster"
  value       = aws_eks_cluster.eks_cluster.name
}

output "role_name" {
  description = "role name"
  value       = aws_iam_role.eks_csi.arn
}
```
Create a file named `custom.tf` and add the following script.
```
data "tls_certificate" "eks" {
  url = aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer
}

resource "aws_iam_role" "eks_csi" {
  assume_role_policy = data.aws_iam_policy_document.eks_csi.json
  name               = "eks-csi"
}

resource "aws_iam_role_policy_attachment" "attach" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
  role       = aws_iam_role.eks_csi.name
}

data "aws_iam_policy_document" "eks_csi" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:ebs-csi-controller-sa"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
      type        = "Federated"
    }
  }
}
```
Create a file named `kong.tf` and add the following script.
```
provider "kubernetes" {
  config_path = var.kube_config_path
}

provider "helm" {
  kubernetes {
    config_path = var.kube_config_path
  }
}

# Generate the self-signed TLS certificate and key
resource "tls_private_key" "tls_key" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384" # Use the secp384r1 curve
}

resource "tls_self_signed_cert" "tls_cert" {
  private_key_pem = tls_private_key.tls_key.private_key_pem
  allowed_uses = [
    "cert_signing",
    "crl_signing",
    "code_signing",
    "server_auth",
    "client_auth",
    "digital_signature",
    "key_encipherment",
  ]
  subject {
    common_name = "kong_clustering"
  }
  validity_period_hours = var.validity
}

resource "kubernetes_namespace" "kong_namespace" {
  metadata {
    name = var.namespace
  }
  depends_on = [
    null_resource.kubectl,
  ]
}

# Create Kubernetes secret for TLS certificate and key
resource "kubernetes_secret" "kong_cluster_cert" {
  metadata {
    name      = "kong-cluster-cert"
    namespace = var.namespace
  }
  data = {
    "tls.crt" = tls_self_signed_cert.tls_cert.cert_pem
    "tls.key" = tls_private_key.tls_key.private_key_pem
  }
  depends_on = [
    kubernetes_namespace.kong_namespace,
  ]
}

resource "helm_release" "kong" {
  name             = "kong-cp"
  repository       = var.helm_repository
  chart            = var.helm_chart
  create_namespace = "true"
  version          = var.chart_version
  namespace        = var.namespace
  values = [templatefile("values-cp.yaml", {
    namespace   = var.namespace
    database    = var.database
    pg_database = var.pg_database
    pg_user     = var.pg_user
    pg_password = var.pg_password
  })]
  depends_on = [
    kubernetes_secret.kong_cluster_cert,
    kubernetes_namespace.kong_namespace,
    helm_release.aws_csi,
  ]
}

resource "helm_release" "kong_dp" {
  name             = "kong-dp"
  repository       = var.helm_repository
  chart            = var.helm_chart
  version          = var.chart_version
  create_namespace = false
  namespace        = var.namespace
  values = [templatefile("values-dp.yaml", {
    namespace = var.namespace
  })]
  depends_on = [
    helm_release.kong,
  ]
}

data "kubernetes_service" "kong-proxy" {
  metadata {
    name      = "kong-dp-kong-proxy"
    namespace = var.namespace
  }
  depends_on = [helm_release.kong_dp]
}

output "kong_proxy_service_ip" {
  value = data.kubernetes_service.kong-proxy.status.0.load_balancer.0.ingress.0.hostname
}

variable "kube_config_path" {
  description = "The path to the Kubernetes config file"
  type        = string
}

variable "chart_version" {
  description = "Version of Kong deployed"
  type        = string
}

variable "namespace" {
  description = "Namespace"
  type        = string
}

variable "helm_repository" {
  description = "The Helm repository URL"
  type        = string
}

variable "validity" {
  description = "The validity period for the TLS certificate in hours"
  type        = number
  default     = 365 * 24
}

variable "helm_chart" {
  description = "The Helm chart name"
  type        = string
}

variable "database" {
  description = "The type of database"
  type        = string
  default     = "postgres"
}

variable "pg_database" {
  description = "The PostgreSQL database name"
  type        = string
  default     = "kong"
}

variable "pg_user" {
  description = "The PostgreSQL user"
  type        = string
  default     = "kong"
}

variable "pg_password" {
  description = "The PostgreSQL password"
  type        = string
  default     = "demo123"
}
```
Next, create a file named `csi_values.yaml` in the same directory.
```
controller:
  serviceAccount:
    annotations:
      eks.amazonaws.com/role-arn: "arn:aws:iam::${account_id}:role/eks-csi"
    automountServiceAccountToken: true
```
Next, create a file named `values-cp.yaml` in the same directory and include the script below.
```
ingressController:
  env:
    publish_service: kong/kong-dp-kong-proxy
    kong_admin_token: kong_admin_password

# Mount the secret created earlier
secretVolumes:
  - kong-cluster-cert

image:
  repository: kong/kong-gateway
  tag: "3.7.0.0"

env:
  admin_gui_url: https://kong-manager.kongtest.demo.cequence.ai
  admin_gui_api_url: https://kong-admin.kongtest.demo.cequence.ai
  admin_gui_session_conf: '{"secret":"secret","storage":"kong","cookie_secure":false}'
  # This is a control_plane node
  role: control_plane
  # These certificates are used for control plane / data plane communication
  cluster_cert: /etc/secrets/kong-cluster-cert/tls.crt
  cluster_cert_key: /etc/secrets/kong-cluster-cert/tls.key

  # Database
  # CHANGE THESE VALUES
  database: "${database}"
  pg_database: "${pg_database}"
  pg_user: "${pg_user}"
  pg_password: "${pg_password}"
  pg_host: "kong-cp-postgresql.${namespace}.svc.cluster.local"
  pg_ssl: "on"

  # Kong Manager password
  password: kong_admin_password

enterprise:
  enabled: true
  rbac:
    enabled: true
    admin_gui_auth: basic-auth

admin:
  enabled: true
  http:
    enabled: true
  tls:
    enabled: false
  ingress:
    enabled: true
    hostname: kong-admin.kongtest.demo.cequence.ai
    path: /
    pathType: Prefix
    ingressClassName: kong

cluster:
  enabled: true
  tls:
    enabled: true

clustertelemetry:
  enabled: true
  tls:
    enabled: true

manager:
  enabled: true
  http:
    enabled: true
  tls:
    enabled: false

  ingress:
    enabled: true
    hostname: kong-manager.kongtest.demo.cequence.ai
    path: /
    pathType: Prefix
    ingressClassName: kong

proxy:
  enabled: false

postgresql:
   enabled: true
   auth:
     password: demo123
```
Then, create another file named `values-dp.yaml` and add the provided script to it.
```
# Do not use Kong Ingress Controller
ingressController:
 enabled: false

image:
 repository: kong/kong-gateway

# Mount the secret created earlier
secretVolumes:
 - kong-cluster-cert

env:
 # data_plane nodes do not have a database
 role: data_plane
 database: "off"

 # Tell the data plane how to connect to the control plane
 cluster_control_plane: "kong-cp-kong-cluster.${namespace}.svc.cluster.local:8005"
 cluster_telemetry_endpoint: "kong-cp-kong-clustertelemetry.${namespace}.svc.cluster.local:8006"

 # Configure control plane / data plane authentication
 lua_ssl_trusted_certificate: /etc/secrets/kong-cluster-cert/tls.crt
 cluster_cert: /etc/secrets/kong-cluster-cert/tls.crt
 cluster_cert_key: /etc/secrets/kong-cluster-cert/tls.key

# Enterprise functionality
enterprise:
 enabled: false
 license_secret: kong-enterprise-license

# The data plane handles proxy traffic only
proxy:
 enabled: true

# These roles are served by the kong-cp deployment
admin:
 enabled: false

manager:
 enabled: false
```
To apply these configuration files:
- Run `terraform init` to initialize the directory and download the necessary provider plugins.
- Run `terraform plan` to generate an execution plan, allowing you to preview the changes Terraform will make to your infrastructure.
- Run `terraform apply` to execute the actions proposed in the Terraform plan.\
Now, Terraform will create the below resources on AWS.
1. VPC
2. Subnet
3. NAT
4. Elastic IP
5. Route Table
6. IAM Role & Policy
7. Security Group
8. Route53
9. EKS Cluster

#### Testing
To test your Kong Gateway's dashboard, you need to access it in your browser using your domain name. 
- Open your browser and enter `https://kong-admin.kongtest.demo.cequence.ai`.
- By pinging the Kong Admin API first, you verify that Kong is running correctly and is accessible.
- Kong Manager relies on the Admin API to function. If the Admin API is not working, Kong Manager will not be able to perform any tasks.
- Open your browser and enter `https://kong-manager.kongtest.demo.cequence.ai`.
- This will open your Kong Manager dashboard in your default web browser, allowing you to test and interact with it directly.

The Kong Admin dashboard should appear as shown below.

![test](https://github.com/Hepzidavid/kong/blob/main/Testing.png)


## Conclusion
Kong API Gateway functions as an intermediary between clients and backend services, effectively managing API traffic. It operates on a plugin-based architecture, allowing developers to extend its functionality according to specific requirements. It offers various features including routing, authentication, rate limiting, logging, and caching, all crucial for API management. Kong relies on a datastore, typically PostgreSQL or Cassandra, to store configuration data and runtime information. Kong provides a user-friendly Admin API and Dashboard for configuration management and monitoring. Overall, Kong's architecture and feature set make it a versatile and powerful tool for managing APIs in a scalable and efficient manner.