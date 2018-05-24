/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"crypto/rand"
	"gopkg.in/yaml.v2"

	netutil "k8s.io/apimachinery/pkg/util/net"
)

/* The pool-tool application is designed to work together with
 * cpumanager pool policy. The application sets the kubelet
 * configuration to match with the loaded profile file on selected
 * nodes. The profiles are yaml files and look like this:
 *
 *      cpupools:
 *        - name: "reserved"
 *          cpus: "0-7,9"
 *        - name: "default"
 *          cpus: "8,10-12"
 *
 * Note that the file format is subject to change in future versions of
 * this tool. The above example would create two cpu pools, reserved and
 * default, and assign cpus 0-7 (inclusive range) and 9 to pool reserved
 * and cpus 8, 10, 11, and 12 to pool default.
 *
 * Usage:
 *	    pool-tool <--profile profile> [--nodes node1,node2,...] [--port 8001] [--address 127.0.0.1]
 *
 * In normal use port and address don't need to be changed, given that
 * the command is run on kubernetes master node.
 *
 * In order for the tool to work, Dynamic Kubelet Configuration must be
 * enabled on API server and kubelet. In 1.11 the feature should be on
 * by default, but 1.10 users will need to enable the feature gate
 * manually. For example, create a directory for the configuration:
 *
 *     # mkdir /var/lib/kubelet/config
 *
 * Then add
 *
 *     --feature-gates=DynamicKubeletConfig=true --dynamic-config-dir=/var/lib/kubelet/config
 *
 * to kubelet command lines and
 *
 *     --feature-gates=DynamicKubeletConfig=true
 *
 * to API server command line. Then run kube-proxy to enable pool-tool to
 * talk to the API server:
 *
 *     $ kubectl proxy -p 8001
 *
 * After this pool-tool will be able to set the kubelet configuration.
 */

// TODO items:
//   * Replace the kubectl calls with k8s go-client API calls
//   * Do the calls inside a specific namespace
//   * Redo the configuration so that the kubelet command-line
//     configuration is compatible with pool-tool
//   * Add ability to request just a number of cores instead of
//     specifying the exact cores
//   * Add an option to control the cleaning up of old resources
//   * Make pool-tool run in a pod
//     * Use keys via secrets

type nodeList []string

func (n *nodeList) String() string {
	return fmt.Sprint(*n)
}

func (n *nodeList) Set(value string) error {
	for _, token := range strings.Split(value, ",") {
		*n = append(*n, token)
	}
	return nil
}

var nodes nodeList

// for data we read out of a node's /stats/summary endpoint

type CpuInfo struct {
	Socketid int
	Coreid   int
}

type StatsYaml struct {
	Node struct {
		Cpupool struct {
			Time     string
			Topology map[string]CpuInfo
			// TODO: Pools
		}
	}
}

// for Node configuration

type NodeSpecConfigSourceConfigMapRefYaml struct {
	Name string
}

type NodeSpecConfigSourceYaml struct {
	ConfigMapRef NodeSpecConfigSourceConfigMapRefYaml `yaml:"configMapRef,omitempty"`
}

type NodeSpecYaml struct {
	ConfigSource NodeSpecConfigSourceYaml `yaml:"configSource,omitempty"`
}

type NodeStatusAddressesYaml struct {
	Address string
	Type    string
}

type NodeStatusYaml struct {
	Addresses []NodeStatusAddressesYaml `yaml:"addresses,omitempty"`
}

type NodeYaml struct {
	Spec   NodeSpecYaml   `yaml:"spec,omitempty"`
	Status NodeStatusYaml `yaml:"status,omitempty"`
}

// for ConfigMaps

type ConfigMapYaml struct {
	Metadata struct {
		Uid  string
		Name string
	}
}

// for profile configuration

type CpuPool struct {
	Name string
	Cpus string
}

type Profile struct {
	Cpupools []CpuPool
}

func loadProfile(fileName string) *Profile {

	profile := Profile{}

	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil
	}

	err = yaml.Unmarshal([]byte(data), &profile)

	if err != nil {
		return nil
	}

	return &profile
}

func downloadNodeTopology(address string, certificate tls.Certificate, ca string, skipCa bool) (StatsYaml, error) {

	url := fmt.Sprintf("https://%s:10250/stats/summary", address)

	certPool := x509.NewCertPool()

	if !skipCa {
		data, err := ioutil.ReadFile(ca)
		if err != nil {
			return StatsYaml{}, err
		}
		certPool.AppendCertsFromPEM(data)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{certificate},
		RootCAs:            certPool,
		InsecureSkipVerify: skipCa,
	}

	client := &http.Client{
		Transport: netutil.SetOldTransportDefaults(&http.Transport{TLSClientConfig: tlsConfig}),
	}
	resp, err := client.Get(url)
	if err != nil {
		return StatsYaml{}, fmt.Errorf("unable to get URL %q: %s", url, err.Error())
	}
	defer resp.Body.Close()

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return StatsYaml{}, fmt.Errorf("failed to read HTTP response: %s", err.Error())
	}

	statsYaml := StatsYaml{}
	err = yaml.Unmarshal(contents, &statsYaml)
	if err != nil {
		return StatsYaml{}, fmt.Errorf("failed to parse stats yaml: %s", err.Error())
	}

	return statsYaml, nil
}

func downloadNodeConfig(nodeName, address, port string) ([]byte, error) {

	url := fmt.Sprintf("http://%s:%s/api/v1/nodes/%s/proxy/configz", address, port, nodeName)

	fmt.Printf("Download config from %s ...\n", url)

	client := &http.Client{Transport: netutil.SetOldTransportDefaults(&http.Transport{})}
	resp, err := client.Get(url)
	if err != nil {
		return []byte{}, fmt.Errorf("unable to get URL %q: %s", url, err.Error())
	}
	defer resp.Body.Close()

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to read HTTP response: %s", err.Error())
	}

	return contents, nil
}

func parseNodeConfig(fileName string) *Profile {

	profile := Profile{}

	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil
	}

	err = yaml.Unmarshal([]byte(data), &profile)

	if err != nil {
		return nil
	}

	return &profile
}

func parseCpuSet(value string) ([]int, int, error) {
	arbitrary := 0
	cpus := make([]int, 0)
	for _, token := range strings.Split(value, ",") {
		rtokens := strings.Split(token, "-")
		if len(rtokens) == 1 {
			// There can be cpu allocations of form "@3", meaning that three
			// arbitrary cpus would be reserved.

			rtokens[0] = strings.TrimSpace(rtokens[0])

			if len(rtokens[0]) >= 1 && rtokens[0][0] == '@' {
				i, err := strconv.Atoi(rtokens[0][1:])
				if err != nil {
					return []int{}, 0, err
				}
				arbitrary += i
			} else {

				i, err := strconv.Atoi(rtokens[0])
				if err != nil {
					return []int{}, 0, err
				}
				cpus = append(cpus, i)
			}
		} else if len(rtokens) == 2 {
			// "4-8" and so.

			rtokens[0] = strings.TrimSpace(rtokens[0])
			rtokens[1] = strings.TrimSpace(rtokens[1])

			i, err := strconv.Atoi(rtokens[0])
			if err != nil {
				return []int{}, 0, err
			}
			j, err := strconv.Atoi(rtokens[1])
			if err != nil {
				return []int{}, 0, err
			}
			if i >= j {
				return []int{}, 0, fmt.Errorf("failed to parse CpuSet: '%s'", value)
			}

			for ; i <= j; i++ {
				cpus = append(cpus, i)
			}
		} else {
			return []int{}, 0, fmt.Errorf("failed to parse CpuSet: '%s'", value)
		}
	}

	return cpus, arbitrary, nil
}

func findSibling(topology map[string]CpuInfo, id int) (int, error) {

	idAsString := fmt.Sprintf("%d", id)

	cpuInfo, ok := topology[idAsString]
	if !ok {
		return 0, fmt.Errorf("Map lookup error for core id %d", id)
	}

	for key, val := range topology {
		if val.Coreid == cpuInfo.Coreid {
			sib, err := strconv.Atoi(key)
			if err != nil {
				return 0, err
			}
			if sib != id {
				// Do not count the original core as the sibling.
				return sib, nil
			}
		}
	}

	return -1, nil
}

func findOfflineSiblings(topology map[string]CpuInfo, profile *Profile) ([]int, []int, error) {

	// Create a list of sibling cores which to turn off. The algorithm
	// is as follows:
	// 1. If the profile has a set of named cores, find the sibling
	//    cores and turn them off.
	// 2. Then, if the profile requests just a number of cores, find
	//    such cores whose sibling doesn't belong to any other cpu pool
	//    and turn the sibling off. Amend the original request so that
	//    it requests certain cores so that the backend doesn't allocate
	//    other cores.

	var htDisabledPool string = ""

	for _, pool := range profile.Cpupools {
		if pool.Name == "no-hyperthreads" {
			htDisabledPool = pool.Cpus
		}
	}

	if htDisabledPool == "" {
		return []int{}, []int{}, nil
	}

	cpus, arbitrary, err := parseCpuSet(htDisabledPool)
	if err != nil {
		return []int{}, []int{}, err
	}

	offlineCpus := make([]int, 0)

	for _, cpu := range cpus {
		sib, err := findSibling(topology, cpu)
		if err != nil {
			return []int{}, []int{}, err
		}
		if sib == -1 {
			// There was no sibling for this core? No need to offline anything.
			continue
		}

		if sib == 0 {
			return []int{}, []int{}, fmt.Errorf("Core 0 can't be offline in Linux systems: can't disable ht for core %d", cpu)
		}

		offlineCpus = append(offlineCpus, sib)
	}

	allReservedCpus := make([]bool, len(topology))

	if arbitrary != 0 {
		// Parse all cpu sets to find out which cores are occupied.
		for _, pool := range profile.Cpupools {
			parsedCpuSet, _, err := parseCpuSet(pool.Cpus)
			if err != nil {
				return []int{}, []int{}, err
			}
			for _, cpuId := range parsedCpuSet {
				if allReservedCpus[cpuId] == true {
					// two pools try to allocate the same cpu
					return []int{}, []int{}, fmt.Errorf("Double allocating CPU %d", cpuId)
				}
				allReservedCpus[cpuId] = true
			}
		}

		// Use a greedy algorithm to find a core which doesn't have the
		// sibling alrady allocated.
		for cpuId, val := range allReservedCpus {
			if !val {
				// Cpu core is not allocated.
				sib, err := findSibling(topology, cpuId)
				if err != nil {
					return []int{}, []int{}, err
				}

				available := true

				// Check if the sibling is allocated from some pool or if we are trying
				// to put core 0 offline.
				if allReservedCpus[sib] || sib == 0 {
					available = false
					break
				}

				if available {
					// Reserve the cpu and the sibling.
					allReservedCpus[sib] = true
					allReservedCpus[cpuId] = true

					// Mark the sibling core to be offloaded.
					offlineCpus = append(offlineCpus, sib)

					// Add the selected cpu to the new ht-disabled cpu
					// pool.
					cpus = append(cpus, cpuId)

					arbitrary--
				}

				if arbitrary == 0 {
					// We could allocate all requested cores, nice!
					break
				}
			}
		}
	}

	if arbitrary != 0 {
		return []int{}, []int{}, fmt.Errorf("Could not allocate all requested non-ht cores.")
	}

	return offlineCpus, cpus, nil
}

func runKubeCtl(cmdLine string) (error, bytes.Buffer, bytes.Buffer) {

	var outBuf, errBuf bytes.Buffer

	cmdTokens := strings.Split(cmdLine, " ")

	cmd := exec.Command("kubectl", cmdTokens...)
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()

	return err, outBuf, errBuf
}

func cpuSliceToCpuSet(cpus []int) string {
	cpusAsStrings := make([]string, len(cpus))

	for i, id := range cpus {
		cpusAsStrings[i] = fmt.Sprintf("%d", id)
	}

	return strings.Join(cpusAsStrings, ",")
}

func main() {

	var profile string
	var address string
	var port string
	var cert string
	var key string
	var ca string
	var skipCa bool
	var dryRun bool

	// Usage:
	//   pool-tool --profile <profile> [--nodes node1,node2,...] [--port 8001] [--address 127.0.0.1] [--cert certname.crt] [--key private.key]

	flag.StringVar(&profile, "profile", "", "Profile file name to apply.")
	flag.StringVar(&address, "address", "127.0.0.1", "API server address.")
	flag.StringVar(&port, "port", "8001", "API server port.")
	flag.Var(&nodes, "nodes", "Comma-sepatared list of node names.")
	flag.StringVar(&cert, "cert", "", "Client certificate file for accessing /stats node endpoint.")
	flag.StringVar(&key, "key", "", "Private key file for the client certificate.")
	flag.StringVar(&ca, "ca", "", "Cluster Certificate Authority.")
	flag.BoolVar(&skipCa, "insecure-skip-ca", false, "Disable CA validation check.")
	flag.BoolVar(&dryRun, "dry-run", false, "Do not really change node configuration.")

	flag.Parse()

	fmt.Printf("profile '%s', nodes '%s'.\n", profile, nodes.String())

	// Load the profile file.
	profileConfig := loadProfile(profile)

	if profileConfig == nil {
		panic("Error loading profile file")
	}

	fmt.Printf("Profile:\n\t%v\n", *profileConfig)

	// If the profile has a pool with special name "no-hyperthreads", we
	// need to get the node CPU topology to find out how to disable
	// the hyperthreading. For this we'll need a client certificate.

	var noHyperThreads bool
	var noHyperThreadsIdx int
	var certificate tls.Certificate

	for i, cpuPool := range profileConfig.Cpupools {
		if cpuPool.Name == "no-hyperthreads" {
			noHyperThreads = true
			noHyperThreadsIdx = i
			break
		}
	}
	if noHyperThreads {
		var err error
		certificate, err = tls.LoadX509KeyPair(cert, key)
		if err != nil {
			panic("'no-hyperthreads' specified, but failed to load client certificate.")
		}
	}

	for _, node := range nodes {

		// Download node status data to get the IP address and currently
		// used ConfigMap
		err, outBuf, errBuf := runKubeCtl("get node " + node + " -o yaml")
		if err != nil {
			fmt.Println(err)
			panic("Error getting current node configuration: " + errBuf.String())
		}
		nodeYaml := NodeYaml{}
		err = yaml.Unmarshal(outBuf.Bytes(), &nodeYaml)
		if err != nil {
			panic("failed to parse node yaml: '" + outBuf.String() + "'")
		}

		if noHyperThreads {

			var address string

			for _, addressItem := range nodeYaml.Status.Addresses {
				if addressItem.Type == "InternalIP" {
					address = addressItem.Address
				}
			}

			if address == "" {
				panic("Not able to find node '" + node + "' IP address")
			}

			// Download node topology
			statsYaml, err := downloadNodeTopology(address, certificate, ca, skipCa)

			if err != nil {
				panic("Failed to download node topology: " + err.Error())
			}

			fmt.Printf("topology: %v\n", statsYaml)

			offline, newNoHyperthreads, err := findOfflineSiblings(statsYaml.Node.Cpupool.Topology, profileConfig)

			if err != nil {
				panic("Failed to find sibling cores to offline: " + err.Error())
			}

			fmt.Printf("Offline logical cores: %v, new HT disabled pool: %v\n", offline, newNoHyperthreads)

			// Make sure that there is no overlap between HT disabled pool and offline
			// pool -- if that happens, the requested configuration is impossible.

			for _, offlineCore := range offline {
				for _, noHtCore := range newNoHyperthreads {
					if noHtCore == offlineCore {
						panic("Requested non-hyperthread configuration is not possible on node " + node + ".")
					}
				}
			}

			// Create a new CPU pool called "offline". This contains the
			// cores that we want to turn off.
			profileConfig.Cpupools = append(profileConfig.Cpupools, CpuPool{
				Name: "offline",
				Cpus: cpuSliceToCpuSet(offline),
			})

			// Update "no-hyperthreads" CPU pool to contain the
			// allocations we made to select cores for requests such as
			// "@4".
			profileConfig.Cpupools[noHyperThreadsIdx] = CpuPool{
				Name: "no-hyperthreads",
				Cpus: cpuSliceToCpuSet(newNoHyperthreads),
			}
		}

		// Get the rest of the configuration from /configz endpoint.
		// TODO: maybe we can assume that the config file containing the
		// node bootstrap parameters is present and kubelet isn't
		// configured with command line parameters? Then creating the
		// ConfigMap based on that file would be enough.
		nodeConfigYaml, err := downloadNodeConfig(node, address, port)
		if err != nil {
			panic("Error downloading config for node " + node + ": " + err.Error())
		}

		nodeConfig := make(map[interface{}]interface{})
		err = yaml.Unmarshal(nodeConfigYaml, &nodeConfig)
		if err != nil {
			panic("Error parsing node configuration.")
		}

		// Change the CPU pool information from profile configuration to
		// a form that is understood by node configuration

		poolConfig := make(map[string]string)
		for _, cpuPool := range profileConfig.Cpupools {
			cpuList := cpuPool.Cpus

			poolConfig[cpuPool.Name] = cpuList
		}

		fmt.Printf("PoolConfig:\n\t%v\n", poolConfig)

		// Add/change the CPUPools data in the node configuration

		nodeConfig["CPUPools"] = poolConfig

		// Add missing "kind" and "apiVersion" fields

		nodeConfig["kind"] = "KubeletConfiguration"
		nodeConfig["apiVersion"] = "kubelet.config.k8s.io/v1beta1"

		// Convert the configuration back to yaml

		data, err := yaml.Marshal(&nodeConfig)
		if err != nil {
			panic("Error marshaling node configuration data to yaml.")
		}

		file, err := ioutil.TempFile("", "pool-tool-node-config")
		if err != nil {
			panic("Error creating temporary file for node configuration.")
		}

		defer func() {
			file.Close()
			os.Remove(file.Name())
		}()

		for n := 0; n < len(data); {
			wrote, err := file.Write(data[n:])
			if err != nil {
				panic("Error writing temporary file for node configuration.")
			}
			n += wrote
		}

		if dryRun {
			return
		}

		// Create short random string to add to the end of the ConfigMap
		// name. This guarantees that we can create ConfigMaps which
		// have the same content with different names, since kubectl's
		// --append-hash option just appends the hash of the ConfigMap's
		// contents to the name.

		r := make([]byte, 16)
		rand.Read(r)
		postfix := fmt.Sprintf("%x", r)

		// Call kubectl to create and push ConfigMap based on the config

		err, outBuf, errBuf = runKubeCtl("-n kube-system create configmap cpu-pool-node-config-" + postfix + " -o yaml --from-file=kubelet=" + file.Name())

		if err != nil {
			fmt.Println(err)
			panic("Error creating ConfigMap: " + errBuf.String())
		}

		// Parse the ConfigMap information from the result

		configMapYaml := ConfigMapYaml{}
		err = yaml.Unmarshal(outBuf.Bytes(), &configMapYaml)
		if err != nil {
			panic("Error parsing ConfigMap.")
		}

		configMapName := configMapYaml.Metadata.Name
		configMapUid := configMapYaml.Metadata.Uid

		fmt.Printf("ConfigMap name: '%s', uid: '%s'\n", configMapName, configMapUid)

		// Add the node permissions to read the ConfigMap

		err, outBuf, errBuf = runKubeCtl("-n kube-system create role --resource=configmap " + configMapName + "-reader --verb=get --resource-name=" + configMapName + " -o name")

		if err != nil {
			fmt.Println(err)
			panic("Error creating role: " + errBuf.String())
		}

		roleName := strings.TrimSpace(outBuf.String())

		err, outBuf, errBuf = runKubeCtl("-n kube-system create rolebinding " + configMapName + "-reader --role=" + configMapName + "-reader --user=system:node:" + node + " -o name")

		if err != nil {
			fmt.Println(err)
			panic("Error creating rolebinding: " + errBuf.String())
		}

		roleBindingName := strings.TrimSpace(outBuf.String())

		// Remove old ConfigMap

		var oldConfigMap string

		oldConfigMap = nodeYaml.Spec.ConfigSource.ConfigMapRef.Name

		// Create a configuration snippet

		snippet := fmt.Sprintf("{\"spec\":{\"configSource\":{\"configMapRef\":{\"name\":\"%s\",\"namespace\":\"kube-system\",\"uid\":\"%s\"}}}}", configMapName, configMapUid)

		// Patch the Node object with the configuration

		err, outBuf, errBuf = runKubeCtl("patch node " + node + " -p " + snippet)

		if err != nil {
			fmt.Println(err)
			panic("Error patching node:\n\t" + errBuf.String() + "\n\t" + outBuf.String() + "\n\t" + snippet)
		}

		fmt.Println("Patched kubelet on node '" + node + "' to use the CPU profile '" + profile + "'.")
		fmt.Println("ConfigMap name: '" + configMapName + "', Role name: '" + roleName + "', RoleBinding name: '" + roleBindingName + "'")

		// Remove the read rights (RoleBinding) from the Node to the old
		// ConfigMap. Also remove the Role and the ConfigMap.  Should we
		// add a label to the map to indicate that it was created by
		// pool-tool?

		if oldConfigMap != "" {
			err, _, errBuf = runKubeCtl("-n kube-system delete rolebinding " + oldConfigMap + "-reader")
			if err != nil {
				fmt.Println(err)
				panic("Error deleting old RoleBinding: " + errBuf.String())
			}
			err, _, errBuf = runKubeCtl("-n kube-system delete role " + oldConfigMap + "-reader")
			if err != nil {
				fmt.Println(err)
				panic("Error deleting old Role: " + errBuf.String())
			}
			err, _, errBuf = runKubeCtl("-n kube-system delete configmap " + oldConfigMap)
			if err != nil {
				fmt.Println(err)
				panic("Error deleting old ConfigMap: " + errBuf.String())
			}
		}
	}
}
