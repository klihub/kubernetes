/*
Copyright 2018 The Kubernetes Authors.

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

package cpumanager

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"encoding/json"

	"google.golang.org/grpc"
	"io"

	"k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/state"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/topology"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"

	api "k8s.io/kubernetes/pkg/kubelet/apis/cpuplugin/v1draft1"
	stub "k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/stub"
)

const (
	// log message prefix
	logPrefix = "[cpumanager/plugin] "
	// PolicyRelay is the well-known name of this CPU Manager policy
	PolicyRelay policyName = "plugin"
	// timeout for starting the plugin
	startupTimeout = 5 * time.Second
	// timeout for handling a request
	requestTimeout = 1 * time.Second
	// key for opaque policy plugin data in the checkpointed state
	pluginStateKey = "pluginstate"
)

// Ensure that relayPolicy implements the necessary interfaces.
var _ Policy = &relayPolicy{}
var _ api.RegistrationServer = &relayPolicy{}

// Allow these native resources to be declared by plugins.
var nativeResources = map[string]bool{
	string(v1.ResourceCPU): true,
}

//
// relayPolicy implements externally pluggable policies as a CPUManager policy.
//

type relayPolicy struct {
	sync.Mutex                            // we're lockable
	topology        *topology.CPUTopology // CPU topology as discovered by the kubelet
	numReservedCPUs int                   // number of CPUs to kube-/system-reserve
	expectedPolicy  string                // requested/expected policy (plugin) name
	updateCapacity  UpdateCapacityFunc    // function to update resource capacity
	socketDir       string                // directory for server and plugin sockets
	server          *grpc.Server          // plugin registration gRPC server
	client          *grpc.ClientConn      // CPU plugin gRPC client connection
	plugin          api.CpuPluginClient   // CPU plugin client stub
	activePolicy    string                // active policy plugin
	vendor          string                // plugin vendor (domain)
	namespace       string                // plugin resource namespace
	state           state.State           // cached CPUManager state/checkpoint
}

// our logger instance
var log = stub.NewLogger(logPrefix)

// NewRelayPolicy creates a new CPUManager plugin/relay policy.
func NewRelayPolicy(topology *topology.CPUTopology, numReservedCPUs int,
	expectedPolicy string, updateCapacity UpdateCapacityFunc) Policy {
	log.Info("creating '%s' CPUManager policy", PolicyRelay)

	r := &relayPolicy{
		topology:        topology,
		numReservedCPUs: numReservedCPUs,
		expectedPolicy:  expectedPolicy,
		updateCapacity:  updateCapacity,
	}

	r.socketDir, _ = filepath.Split(api.CpuManagerSocket)

	return r
}

// Name returns the well-known name for the plugin/relay policy.
func (r *relayPolicy) Name() string {
	return string(PolicyRelay)
}

// Start the plugin/relay policy.
func (r *relayPolicy) Start(s state.State) {
	log.Info("starting %s policy", PolicyRelay)

	r.validateState(s)
	r.ensureDefaultCPUSet()
	r.startRegistrationServer()
}

// Allocate CPU and related resources for the given container.
func (r *relayPolicy) AddContainer(s state.State, pod *v1.Pod, container *v1.Container, containerID string) error {
	r.Lock()
	defer r.Unlock()

	if !r.hasPlugin() {
		return nil
	}

	r.assertState(s)

	return r.addContainer(pod, container, containerID)
}

// Release CPU and related resources allocated for the given container.
func (r *relayPolicy) RemoveContainer(s state.State, containerID string) error {
	r.Lock()
	defer r.Unlock()

	if !r.hasPlugin() {
		//
		// Notes:
		//   It is safe to simply ignore AddContainer requests while we're running
		//   without a registered policy plugin. The reconcilation loop will retry
		//   the request until/unless the container has an associated CPUSet in the
		//   checkpointed state.
		//
		//   However, the same is not true for RemoveContainer. Reconcilation does
		//   not try to detect if a RemoveContainer request had not been properly
		//   performed. The reason for this is that with the stock policies (well,
		//   single policy really) container running on the default CPUSet never
		//   get added to the state at all. The CPU Manager has no way of finding
		//   out if/when such a container has been removed but is still lingering
		//   in the CPU Manager.
		//
		//   Therefore, if we get a RemoveContainer request while running without
		//   a policy plugin, we simply remove the container from the state. Plugins
		//   should save all active containers in their private plugin data and
		//   remove lingering ones when they get Start()ed after registration.
		//
		//   Another alternative would be to cache in the checkpointed state the IDs
		//   of all containers that have not been removed from the policy plugin yet
		//   and generate a remove request for each once the plugin is fully set up
		//   and running.
		//

		log.Warning("no policy plugin, purging container %s from state", containerID)

		r.state.Delete(containerID)
		return nil
	}

	r.assertState(s)

	return r.removeContainer(containerID)
}

// Process container update events.
func (r *relayPolicy) processUpdateEvent(event *api.UpdateContainerEvent) error {
	log.Info("received (unsolicited) container update event: %+v", event)
	return nil
}

// Check if a policy plugin is registered/active.
func (r *relayPolicy) hasPlugin() bool {
	return r.client != nil
}

// Validate the supplied state.
func (r *relayPolicy) validateState(s state.State) error {
	//
	// Actual state validation is performed by the plugin during the
	// initial cross-registration phase, once the plugin shows up.
	//

	r.state = s
	return nil
}

// Check that the supplied state is the same as the cached one.
func (r *relayPolicy) assertState(s state.State) {
	if r.state != s {
		log.Panic("inconsistent cached vs. supplied state: %+v != %+v", r.state, s)
	}
}

// Ensure that we have a non-empty default CPU set.
func (r *relayPolicy) ensureDefaultCPUSet() {
	//
	// The first time we start, we start off a clean slate. We do not have
	// a default CPU set to rely on and we won't have one until the plugin
	// gets around to register with us. Until that time we temporarily set
	// up the to be reserved CPU set as the default one. This usually means
	// that we end up starting pods off CPU 0.
	// As long as all policy plugins allocate reserved CPUs starting with
	// CPU 0 this should be a rather safe bet.
	//

	if !r.state.GetDefaultCPUSet().IsEmpty() {
		return
	}

	cpus := r.topology.CPUDetails.CPUs()
	tmp, _ := takeByTopology(r.topology, cpus, r.numReservedCPUs)

	if tmp.Size() != r.numReservedCPUs {
		log.Panic("failed to allocate reserved CPUs as temporary default set")
	}

	log.Info("temporary default CPU set %s", tmp.String())

	r.state.SetDefaultCPUSet(tmp)
}

// Start and configure the registered CPU plugin.
func (r *relayPolicy) startPlugin() error {
	log.Info("starting CPU policy '%s'", r.activePolicy)

	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	reply, err := r.plugin.Start(ctx, &api.StartRequest{
		Topology:        stub.StubCPUTopology(*r.topology),
		NumReservedCPUs: int32(r.numReservedCPUs),
		State:           r.stubState(),
	})

	if err != nil {
		return err
	}

	if err := r.updatePluginResources(reply.Resources); err != nil {
		return err
	}

	if err := r.applyStateChanges(reply.State); err != nil {
		return err
	}

	return nil
}

// Relay an AddContainer request to the plugin.
func (r *relayPolicy) addContainer(pod *v1.Pod, container *v1.Container, containerID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	reply, err := r.plugin.AddContainer(ctx, &api.AddContainerRequest{
		Id:        containerID,
		Pod:       stub.StubPod(*pod),
		Container: stub.StubContainer(*container),
	})

	if err != nil {
		return err
	}

	if err := r.applyContainerHints(reply.Hints); err != nil {
		return err
	}

	if err := r.updatePluginResources(reply.Resources); err != nil {
		return err
	}

	if err := r.applyStateChanges(reply.State); err != nil {
		return err
	}

	return nil
}

// Relay a RemoveContainer request to the plugin.
func (r *relayPolicy) removeContainer(containerID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	reply, err := r.plugin.RemoveContainer(ctx, &api.RemoveContainerRequest{
		Id:        containerID,
	})

	if err != nil {
		return err
	}

	if err := r.applyContainerHints(reply.Hints); err != nil {
		return err
	}

	if err := r.updatePluginResources(reply.Resources); err != nil {
		return err
	}

	if err := r.applyStateChanges(reply.State); err != nil {
		return err
	}

	return nil
}

// Apply container resource allocations changes requested by the plugin.
func (r *relayPolicy) applyContainerHints(hints map[string]*api.ContainerHint) error {
	if hints == nil {
		return nil
	}

	for _, h := range hints {
		if h.Cpuset == stub.DeletedContainer {
			r.state.Delete(h.Id)
		} else {
			cset, err := cpuset.Parse(h.Cpuset)
			if err != nil {
				return err
			}
			r.state.SetCPUSet(h.Id, cset)
		}
	}

	return nil
}

// Apply resource capacity declaration changes requested by the plugin.
func (r *relayPolicy) updatePluginResources(resources map[string]*api.Quantity) error {
	updates := v1.ResourceList{}

	for name, qty := range resources {
		if !strings.HasPrefix(name, r.namespace) {
			if !nativeResources[name] {
				name = r.namespace + name
			}
		}
		res := v1.ResourceName(name)
		updates[res] = stub.CoreQuantity(qty)
		log.Info("declaring plugin resource %s: %s", name, qty.Value)
	}

	if len(updates) > 0 {
		r.updateCapacity(updates)
	}

	return nil
}

// Apply changes to the checkpointed state requested by the plugin.
func (r *relayPolicy) applyStateChanges(as *api.State) error {
	if as == nil {
		return nil
	}

	cset, err := cpuset.Parse(as.DefaultCPUSet)
	if err != nil {
		return err
	}
	pstate, err := json.Marshal(as.PluginState)
	if err != nil {
		return err
	}

	r.state.SetDefaultCPUSet(cset)
	r.state.SetPolicyEntry(pluginStateKey, string(pstate))

	return nil
}

//
// CPUManager plugin registration server
//

// Register is called by the CPU plugin to register itself as the active plugin.
func (r *relayPolicy) Register(ctx context.Context, req *api.RegisterRequest) (*api.Empty, error) {
	r.Lock()
	defer r.Unlock()

	log.Info("registering '%s' CPUManager policy plugin, version %s",
		req.Name, req.Version)

	if err := r.validatePlugin(req); err != nil {
		log.Error("rejecting plugin '%s': %s", req.Name, err.Error())
		return &api.Empty{}, err
	}


	if err := r.registerPluginClient(req); err != nil {
		log.Error("failed to register to plugin '%s': %s", req.Name, err.Error())
		return &api.Empty{}, err
	}


	if err := r.startPlugin(); err != nil {
		log.Error("failed to register to plugin '%s': %s", req.Name, err.Error())
		r.cleanupClientConnection()
		return &api.Empty{}, err
	}

	if err := r.watchUpdateEvents(); err != nil {
		log.Error("failed to set up event watch for unsolicited container updates: %s", err.Error())
		r.cleanupClientConnection()
		return &api.Empty{}, err
	}

	return &api.Empty{}, nil
}

// Validate the registrating plugin against our configuration.
func (r *relayPolicy) validatePlugin(req *api.RegisterRequest) error {
	if req.Version != api.Version {
		return fmt.Errorf("incorrect API version (plugin %s, expected %s, provided %s)",
			req.Name, req.Version, api.Version)
	}

	if r.expectedPolicy != "" && r.expectedPolicy != req.Name {
		return fmt.Errorf("unexpected policy plugin '%s', expecting '%s'",
			req.Name, r.expectedPolicy)
	}

	if r.client != nil {
		return fmt.Errorf("unexpected policy plugin '%s', already registered with '%s'",
			req.Name, r.expectedPolicy)
	}

	return nil
}

// Start up the plugin registration gRPC server.
func (r *relayPolicy) startRegistrationServer() {
	log.Info("starting CPU policy plugin registration server")

	if err := os.MkdirAll(r.socketDir, 0755); err != nil {
		log.Panic("failed to create socket directory: %s", err.Error())
	}

	// Clean up old sockets. This will stop and restart any running plugins.
	if err := r.cleanupSockets(); err != nil {
		log.Panic("failed to clean up sockets: %s", err.Error())
	}

	// Create socket, start the registration server on it.
	lis, err := net.Listen("unix", api.CpuManagerSocket)
	if err != nil {
		log.Panic("failed to create/listen on socket %s: %s", api.CpuManagerSocket, err.Error())
	}

	r.server = grpc.NewServer([]grpc.ServerOption{}...)
	api.RegisterRegistrationServer(r.server, r)
	go func () {
		log.Info("starting CPU plugin registration server at %s", api.CpuManagerSocket)
		r.server.Serve(lis)
	}()
}

// Clean up any lingering/old server and plugin sockets.
func (r *relayPolicy) cleanupSockets() error {
	dir, err := os.Open(r.socketDir)
	if err != nil {
		return err
	}
	defer dir.Close()

	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil
	}

	for _, name := range names {
		path := filepath.Join(r.socketDir, name)
		st, err := os.Stat(path)
		if err != nil {
			return err
		}

		if st.IsDir() {
			continue
		}

		if err = os.Remove(path); err != nil {
			return err
		}
	}

	return nil
}

//
// CPU plugin client/stub
//

// Register with the CPU plugin that is registering to us.
func (r *relayPolicy) registerPluginClient(req *api.RegisterRequest) error {
	policy := req.Name
	vendor := req.Vendor
	socket := filepath.Join(api.CpuPluginPath, policy) + ".sock"

	conn, err := grpc.Dial(socket, grpc.WithInsecure(), grpc.WithBlock(),
		grpc.WithDialer(func (socket string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", socket, timeout)
		}))
	if err != nil {
		return err
	}

	r.activePolicy = policy
	r.vendor = vendor
	r.namespace = vendor + "/"
	r.client = conn
	r.plugin = api.NewCpuPluginClient(conn)

	return nil
}

// Close and clean up connection to the registered CPU plugin.
func (r *relayPolicy) stopPluginClient() {
	r.Lock()
	defer r.Unlock()

	r.cleanupClientConnection()
}

// Close and clean up connection to the registered CPU plugin.
func (r *relayPolicy) cleanupClientConnection() {
	if r.client == nil {
		return
	}

	r.client.Close()
	r.client = nil
	r.activePolicy = ""
}

// Monitor (unsolicited) container update events from the plugin.
func (r *relayPolicy) watchUpdateEvents() error {
	log.Info("starting (unsolicited) container update event watch")

	ctx := context.Background()
	stream, err := r.plugin.WatchContainerUpdates(ctx, &api.Empty{})
	if err != nil {
		return err
	}

	go func (ctx context.Context, stream api.CpuPlugin_WatchContainerUpdatesClient) {
		for {
			event, err := stream.Recv()

			if err == io.EOF {
				log.Info("CPU plugin '%s' is gone", r.activePolicy)
				r.stopPluginClient()
				return
			}
			if err != nil {
				log.Error("failed to receive container update event: %s", err.Error())
				r.stopPluginClient()
				return
			}

			r.processUpdateEvent(event)
		}
	}(ctx, stream)

	return nil
}

// Create a plugin/stub state from the current CPUManager state.
func (r *relayPolicy) stubState() *api.State {
	pstate := make(map[string]string)
	if psaved, found := r.state.GetPolicyEntry(pluginStateKey); found {
		json.Unmarshal([]byte(psaved), &pstate)
	}

	state := &api.State{
		Assignments:   make(map[string]string),
		DefaultCPUSet: r.state.GetDefaultCPUSet().String(),
		PluginState:   pstate,
	}

	for id, cset := range r.state.GetCPUAssignments() {
		state.Assignments[id] = cset.String()
	}

	return state
}

