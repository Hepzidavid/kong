provider "kubernetes" {
  config_path = "~/.kube/config"
}


provider "helm" {
  kubernetes {
    config_path = "~/.kube/config"
  }
}

# Terraform code to generate TLS certificate and key using OpenSSL and create a Kubernetes secret

# Create a provider configuration if needed
# Generate the self-signed TLS certificate and key
resource "tls_private_key" "tls_key" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P384" # Use the secp384r1 curve
}

resource "tls_self_signed_cert" "tls_cert" {
  private_key_pem = tls_private_key.tls_key.private_key_pem
  allowed_uses    = [
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

  validity_period_hours = 1095 * 24 # 1095 days
}

# Create Kubernetes secret for TLS certificate and key
resource "kubernetes_secret" "kong_cluster_cert" {
  metadata {
    name      = "kong-cluster-cert"
    namespace = "kong"
  }

  data = {
    "tls.crt" = tls_self_signed_cert.tls_cert.cert_pem
    "tls.key" = tls_private_key.tls_key.private_key_pem
  }
}

resource "null_resource" "secret" {
  # This resource is used to execute a local command to create the Kubernetes secret
  triggers = {
    # Trigger the command execution whenever the TLS certificate or key changes
    tls_certificate_key = "${tls_self_signed_cert.tls_cert.cert_pem}${tls_private_key.tls_key.private_key_pem}"
  }

provisioner "local-exec" {
    command = <<-EOT
      echo "${tls_self_signed_cert.tls_cert.cert_pem}" > /tmp/tls.crt
      echo "${tls_private_key.tls_key.private_key_pem}" > /tmp/tls.key
      kubectl create secret tls kong-cluster-cert \
        --cert=/tmp/tls.crt \
        --key=/tmp/tls.key \
        -n kong
      rm /tmp/tls.crt /tmp/tls.key
    EOT
  }
}


resource "helm_release" "kong" {
  name             = "kong-cp"
  repository       = "https://charts.konghq.com"
  chart            = "kong"
  create_namespace = "true"
  namespace        = "kong"
  values = [
    "${file("values-cp.yaml")}"
  ]
  depends_on = [null_resource.secret]
}
