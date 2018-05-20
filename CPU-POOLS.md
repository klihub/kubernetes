## Introduction

This is a modified version of the corresponding branch of the stock
Kubernetes git tree. The set of extra patches in this tree introduces
the concept of CPU pools to Kubernetes. CPU pools allow the administrator
to partition a node’s CPU cores into pools. Workloads can then request CPU
resources from a given pool using extended resources. This guides the
scheduler to place the workload only on nodes that can fulfill the pool
request. Once scheduled to a capable node, a new CPUManager policy, the
pool policy, arranges for the workload to be run on CPU cores belonging
to the correct pool.

There are various reasons why one might want to further partition CPUs
in a node, including

* To divide and reserve CPU capacity between classes of commonly run
workloads and do so with better resolution than what is achievable by
dedicating full nodes to classes of workloads.

* To reserve CPUs with certain characteristics for high-priority workloads
or workloads that are known to benefit the most from this. One example of
this could be reserving the best turbo-boostable cores in a node for
special workloads. Another example could be running some workloads with
some particular CPU configuration, for instance only on cores which have
HT disabled.

* To isolate and protect unrelated workloads from ones which are known to
potentially cause a dynamic change in overall system behaviour which might
lead to performance degradation in other workloads if they happen to run
on particular cores wrt. the one executing the offending workload. For
instance, dedicate some cores to workloads which heavily utilise AVX-512
instructions.

## Building CPU Pool Support

There are two Kubernetes components which implement the core of CPU pool
support. Furthermore there is a new utility for monitoring and configuring
CPU pools, as well as switching between pre-defined pool setups.

The new Kubernetes additions are the 'CpuPool' mutating admission controller
and the 'pool' CPUManager policy backend. The new pool configuration and
monitoring utility is 'pool-tool'.

### Building the CpuPool Admission Controller

The CpuPool admission controller is a plugin in the Kubernetes API server,
kube-apiserver. You can build from this git tree by building kube-apiserver,
for instance by executing

```
 make KUBE_VERBOSE=1 KUBE_RELEASE_RUN_TESTS=n KUBE_FASTBUILD=true WHAT=cmd/kube-apiserver
```

A successfuly build On a 64-bit Linux system this will produce the binary as

```
_output/local/bin/linux/amd64/kube-apiserver
```

relative to the top of your git tree.

### Building the 'pool' CPUManager policy Backend

The 'pool' CPUManager policy backend is part of kubelet, there to build it you
simply need to build kubelet from this tree, for instance with the following
command:

```
 make KUBE_VERBOSE=1 KUBE_RELEASE_RUN_TESTS=n KUBE_FASTBUILD=true WHAT=cmd/kubelet
```

A successfuly build On a 64-bit Linux system this will produce the binary as

```
_output/local/bin/linux/amd64/kubelet
```

relative to the top of your git tree.

### Building the Pool Configuration and Monitoring Utility, pool-tool

Pool-tool is a separate stanalone binary. You can build with the following
command:

```
 make KUBE_VERBOSE=1 KUBE_RELEASE_RUN_TESTS=n KUBE_FASTBUILD=true WHAT=test/kubelet/pool-tool
```

A successfuly build On a 64-bit Linux system this will produce the binary as

```
_output/local/bin/linux/amd64/pool-tool
```

## Taking CPU Pools Into Use in Your Cluster

To enable CPU pool support, you need to change the two affected components
of your cluster, kubelet and kube-apiserver, with the versions you compiled
from this git tree.

Kubelet is run natively on every node of your cluster, so you will need to
copy (or make it otherwise available, for instance using NFS) to every node.
It is typically started by systemd so we provide a sample configuration here
showing how you can modify your systemd configuration to override the location
and configuration of kubelet.

Kube-apiserver is run on your master node as a pod. The binary can be updated
by creating a modified version of the pod image and serving it from a locally
hosted docker registry. However, since the configuration/manifest of the
apiserver needs to be modified as well, it is easier to set up the manifest
to mount an extra part of the host filesystem as a volume inside the apiserver
container and run the binary from that mount. This is what our example shows.

### Updating kubelet

For every node of your cluster, copy the updated kubelet binary to your node:

```
scp /path/to/repo/_output/local/bin/linux/amd64/kubelet root@$node:/usr/local/bin
```

Next, on every node override the kubelet service to run your compiled binary:

```
# Copy kubelet service to a locally overridable location, if necessary.
mkdir -p /etc/systemd/system
if [ -f /usr/lib/systemd/system/kubelet.service ]; then
    cp /usr/lib/systemd/system/kubelet.service /etc/systemd/system
fi

# Override kubelet location and configuration.
mkdir -p /etc/systemd/system/kubelet.service.d
cat <<EOF
[Service]
Environment="KUBELET_KUBECONFIG_ARGS=--bootstrap-kubeconfig=/etc/kubernetes/boot
strap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf"
Environment="KUBELET_SYSTEM_PODS_ARGS=--pod-manifest-path=/etc/kubernetes/manife
sts --allow-privileged=true"
Environment="KUBELET_NETWORK_ARGS=--network-plugin=cni --cni-conf-dir=/etc/cni/n
et.d --cni-bin-dir=/opt/cni/bin"
Environment="KUBELET_DNS_ARGS=--cluster-dns=10.96.0.10 --cluster-domain=cluster.
local"
Environment="KUBELET_AUTHZ_ARGS=--authorization-mode=Webhook --client-ca-file=/e
tc/kubernetes/pki/ca.crt"
Environment="KUBELET_CADVISOR_ARGS=--cadvisor-port=0"
Environment="KUBELET_CGROUP_ARGS=--cgroup-driver=systemd"
Environment="KUBELET_CERTIFICATE_ARGS=--rotate-certificates=true --cert-dir=/var
/lib/kubelet/pki"
ExecStart=
ExecStart=/usr/local/bin/kubelet \$KUBELET_KUBECONFIG_ARGS \$KUBELET_SYSTEM_PODS_ARGS \$KUBELET_NETWORK_ARGS \$KUBELET_DNS_ARGS \$KUBELET_AUTHZ_ARGS \$KUBELET_CADVISOR_ARGS \$KUBELET_CGROUP_ARGS \$KUBELET_CERTIFICATE_ARGS \$KUBELET_EXTRA_ARGS
EOF > /etc/systemd/system/kubelet.service.d/10-kubelet-binary.conf
```

Next, on every node, enable CPU pool support:

```
# Enable CPU Pools.
cat << EOF
[Service]
Environment="KUBELET_EXTRA_ARGS=--feature-gates=CPUManager=true --cpu-manager-policy=pool --kube-reserved=cpu=800m"
EOF > /etc/systemd/system/kubelet.service.d/20-cpu-pools.conf
```

Finally, on every node, restart the kubelet service:

```
# Restart kubelet
systemctl daemon-reload
systemctl restart kubelet.service
```

### Updating kube-apiserver

Copy the updated kube-apiserver binary to your master mode:

```
scp /path/to/repo/_output/local/bin/linux/amd64/kube-apiserver root@$master:/usr/local/bin
```

Next, on you master node, modify the apiserver manifest to run the updated
binary by including this in /etc/kubernetes/manifests/kube-apiserver.yaml:

```
...
spec:
  containers:
  - command:
    - /cpu-pools/kube-apiserver
...
    volumeMounts:
    - mountPath: /etc/pki
      name: ca-certs-etc-pki
      readOnly: true
...
    - mountPath: /usr/local/bin
      name: cpu-pools
      readOnly: true
  hostNetwork: true
  volumes:
  - hostPath:
      path: /etc/ssl/certs
      type: DirectoryOrCreate
    name: ca-certs
...
  - hostPath:
      path: /cpu-pools
      type: DirectoryOrCreate
    name: cpu-pools
status: {}

```

Next, on your master node, enable the CpuPool admission controller. Do this
by appending it to the list of enabled admission controllers in the manifest
/etc/kubernetes/manifests/kube-apiserver.yaml, like this:

```
...
spec:
  containers:
  - command:
    - /cpu-pools/kube-apiserver
...
    - --feature-gates=CPUManager=True
    - --admission-control=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,NodeRestriction,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota,CpuPool
...
```

In principle you should not do anything to activate these changes. Kubelet
monitors the manifest directory and tries to activate automatically any
changes.

### Make the Pool Configuration and Monitoring Utility Availble

Assuming you usually manage your cluster from within the master node,
copy the pool configuration and monitoring utility, pool-tool to your
master node:

```
scp /path/to/repo/_output/local/bin/linux/amd64/pool-tool root@$master:/usr/local/bin
```

### Enabling Pool Reconfiguration by pool-tool

In order for pool-tool to do its work, you must enable Dynamic Kubelet
Configuration for the API server and kubelet. In Kubernetes 1.11 and
later the feature should be on by default, but in 1.10 users need to
enable the feature gate manually.

First, create a directory for the configuration:

```
mkdir /var/lib/kubelet/config
```

Then add the related command-line options to the kubelet command line:

```
cat <<EOF
[Service]
Environment="KUBELET_DYNAMIC_CONFIG_ARGS=--feature-gates=DynamicKubeletConfig=true --dynamic-config-dir=/var/lib/kubelet/config"
ExecStart=
ExecStart=/usr/local/bin/kubelet \$KUBELET_KUBECONFIG_ARGS \$KUBELET_SYSTEM_PODS_ARGS \$KUBELET_NETWORK_ARGS \$KUBELET_DNS_ARGS \$KUBELET_AUTHZ_ARGS \$KUBELET_CADVISOR_ARGS \$KUBELET_CGROUP_ARGS \$KUBELET_CERTIFICATE_ARGS \$KUBELET_EXTRA_ARGS
\$KUBELET_DYNAMIC_CONFIG_ARGS
EOF > /etc/systemd/system/kubelet.service.d/30-kubelet-binary.conf
```

Next, enable the same feature for the API server by including the following
snippet in /etc/kubernetes/manifests/kube-apiserver.yaml:

```
...
spec:
  containers:
  - command:
    - /cpu-pools/kube-apiserver
...
    --feature-gates=DynamicKubeletConfig=true
...
```

Finally, run kube-proxy to enable pool-tool to talk to the API server:

```
kubectl proxy -p 8001
```

With all of these in place, pool-tool should be able to alter the kubelet
configuration.

## Using pool-tool to Switch Between Different Configurations

