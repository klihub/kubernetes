#!/bin/bash

# In order to access the nodes' stats endpoint (at
# https://<nodename>:10250/stats ) we need to have a client certificate,
# which is signed by the cluster CA and is bound with the correct role
# to have read access to the correct endpoint. Note that this "script"
# is not meant to be run as a script, but you possibly need to amend the
# commands to fit your environment and certificate policy. The outcome
# is a certificate and key pair which can be used to access the
# endpoints.

# Generate an RSA key.
openssl genrsa -out private.pem 2048

# Genereate a certificate signing request for user "system:pooltool"
# with group "pooltool". Note that if you change the user name, you'll
# have to change the user name in subsequent commands. The group name is
# strictly not needed, but can be useful if you want to do group-based
# authentication.
openssl req -new -key private.pem  -out pooltool-csr.pem -subj "/CN=system:pooltool/O=pooltool"

# Generate a CSR in kubernetes. The administrator can accept the CSR
# later to sign the client certificate.
cat <<EOF | kubectl create -f -
apiVersion: certificates.k8s.io/v1beta1
kind: CertificateSigningRequest
metadata:
  name: system:pooltool
spec:
  groups:
  - system:authenticated
  request: $(cat pooltool-csr.pem | base64 | tr -d '\n')
  usages:
  - client auth
EOF

# Execute the following two commands as an kubernetes administrator:
# 1. Check that the request is fine
kubectl describe csr system:pooltool
# 2. Approve the request
kubectl certificate approve system:pooltool

# Download the signed certificate.
kubectl get csr system:pooltool -o jsonpath='{.status.certificate}' | base64 -d > pooltool.crt

# Create a Role for accessing nodes' /stats endpoint. Note two things:
# First, the role is limited to the /stats endpoint for nodes using HTTP
# GET request. Second, the role is cluster-wide, meaning you can access
# all nodes with the certificate.
cat <<EOF | kubectl create -f -
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRole
metadata:
  name: node-stats-reader
rules:
- apiGroups:
  - ""
  resources:
  - nodes/stats
  verbs:
  - "get"
EOF

# Create a RoleBinding. This associates the user in the certificate
# ("system:pooltool") with the role we just created
# ("node-stats-reader").
cat <<EOF | kubectl create -f -
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: pooltool-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: node-stats-reader
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: User
  name: system:pooltool
EOF

# Optional: Check that the certificate works. Note that you can remove
# --no-check-certificate" if your cluster's CA certificate is trusted
# (survives the certificate check). Also, you can replace "localhost"
# with a suitable node IP address.
wget --no-check-certificate --ca-cert=/etc/kubernetes/pki/ca.crt --certificate=pooltool.crt --private-key=private.pem https://localhost:10250/stats/summary
