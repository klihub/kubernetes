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

package poolcache

import (
	"fmt"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	stats "k8s.io/kubernetes/pkg/kubelet/apis/stats/v1alpha1"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpumanager/topology"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
)

type poolCache struct {
	sync.RWMutex
	pools    map[string]stats.CPUPoolUsage
	topology map[int]stats.CPUInfoStats
}

type PoolCache interface {
	IsInitialized() bool
	GetCPUPoolStats() stats.CPUPoolStats
	UpdatePool(pool string, shared, exclusive cpuset.CPUSet, capacity, usage int64)
	AddContainer(pool, id, pod, name string, cpu int64)
	RemoveContainer(pool, id string)
	String() string
}

var _ PoolCache = &poolCache{}

var cache *poolCache

// singleton pattern, TODO: check concurrency
func NewCPUPoolCache(cpuTopology *topology.CPUTopology) PoolCache {
	if cache == nil {

		// Get the CPU topology. For now, it's assumed not to change
		// during kubelet lifetime.
		topo := make(map[int]stats.CPUInfoStats)
		for id, info := range cpuTopology.CPUDetails {
			infoStats := stats.CPUInfoStats{
				SocketID: info.SocketID,
				CoreID:   info.CoreID,
			}
			topo[id] = infoStats
		}

		cache = &poolCache{
			pools:    make(map[string]stats.CPUPoolUsage),
			topology: topo,
		}
	}

	return cache
}

func GetCPUPoolCache() PoolCache {
	return cache
}

func (c *poolCache) UpdatePool(pool string, shared, exclusive cpuset.CPUSet, capacity, usage int64) {
	c.Lock()
	defer c.Unlock()

	p, ok := c.pools[pool]
	if !ok {
		p = stats.CPUPoolUsage{
			Name:       pool,
			Containers: make(map[string]stats.CPUPoolContainer),
		}
	}

	p.SharedCPUs = shared.String()
	p.ExclusiveCPUs = exclusive.String()
	p.Capacity = capacity
	p.Usage = usage

	c.pools[pool] = p
}

func (c *poolCache) AddContainer(pool, cid, pod, name string, cpu int64) {
	c.Lock()
	defer c.Unlock()

	if p, ok := c.pools[pool]; ok {
		p.Containers[cid] = stats.CPUPoolContainer{
			ID:        cid,
			Pod:       pod,
			Container: name,
			Time:      metav1.NewTime(time.Now()),
			CPU:       cpu,
		}
	}
}

func (c *poolCache) RemoveContainer(pool, cid string) {
	c.Lock()
	defer c.Unlock()

	if p, ok := c.pools[pool]; ok {
		delete(p.Containers, cid)
	}
}

func (c *poolCache) GetCPUPoolStats() stats.CPUPoolStats {
	c.RLock()
	defer c.RUnlock()

	pools := make(map[string]stats.CPUPoolUsage)

	for pool, usage := range c.pools {
		pools[pool] = usage
	}

	return stats.CPUPoolStats{
		Time:     metav1.NewTime(time.Now()),
		Pools:    pools,
		Topology: c.topology,
	}
}

func (c *poolCache) IsInitialized() bool {
	return c != nil
}

func (c *poolCache) String() string {

	pools := make([]string, len(c.pools))
	i := 0

	for pool, d := range c.pools {
		pools[i] = fmt.Sprintf("pools[%s]: shared=%s, exclusive=%s, capacity=%d, usage=%d",
			pool, d.SharedCPUs, d.ExclusiveCPUs, d.Capacity, d.Usage)
		i++
	}

	return strings.Join(pools, "\n")
}
