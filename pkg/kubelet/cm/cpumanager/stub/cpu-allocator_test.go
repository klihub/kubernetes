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

package stub

import (
	"fmt"
	"testing"
	"k8s.io/kubernetes/pkg/kubelet/cm/cpuset"
)

type mockTopology struct {
	name string             // test topology name
	packages int            // number of physical packages
	nodes    int            // number of NUMA nodes per package
	cores    int            // number of cores in a package
	threads  int            // number of threads in a core
	offline  string         // offline CPUs
}

type simpleAllocTest struct {
	config   string         // name of topology to use
	topology mockTopology   // corresponding topology
	alloc    []int          // series of CPU allocations
	acheck   []string       // expected allocation results
	release  []int          // series of CPU releases
	rcheck   []string       // expected release results
}


func runSimpleAllocTest(s *simpleAllocTest, t *testing.T) error {
	sys, err := mockSystemInfo(
		s.topology.packages,
		s.topology.nodes,
		s.topology.cores,
		s.topology.threads,
		s.topology.offline)
	if err != nil {
		return fmt.Errorf("%s: failed to set up mock SystemInfo: %v", s.config, err)
	}

	sys.Dump()

	from := sys.OnlineCPUSet()
	for i := range s.alloc {
		src  := from.String()
		ncpu := s.alloc[i]
		aset, err := AllocateCpus(&from, ncpu)

		if err != nil {
			return fmt.Errorf("%s: failed to allocate %d cpus from %s: %v", s.config, ncpu, src, err)
		}

		chk := cpuset.MustParse(s.acheck[i])
		if !aset.Equals(chk) {
			return fmt.Errorf("%s: allocate %d cpus from %s: expected %s, got %s", s.config, ncpu, src,
				s.acheck[i], aset.String())
		}

		t.Logf("%s: allocated %d cpus from %s: %s\n", s.config, aset.Size(), src, aset.String())

		if i >= len(s.release) {
			continue
		}

		src  = aset.String()
		ncpu = s.release[i]
		rset, err := ReleaseCpus(&aset, ncpu)

		if err != nil {
			return fmt.Errorf("%s: failed to free %d cpus from %s: %v", s.config, ncpu, src, err)
		}

		chk = cpuset.MustParse(s.rcheck[i])
		if !aset.Equals(chk) {
			return fmt.Errorf("%s: release %d cpus from %s: expected %s, got %s", s.config, ncpu, src,
				s.rcheck[i], rset.String())
		}

		t.Logf("%s: released %d cpus from %s: %s\n", s.config, ncpu, src, rset.String())
	}

	return nil
}


func TestAllocations(t *testing.T) {
	topologies := make(map[string]mockTopology)
	for _, topology := range []mockTopology{
		{ name: "2/10/2"  ,
			packages: 2,           cores: 10, threads: 2, offline: ""             },
		{ name: "1/16/1"  ,
			packages: 1,           cores: 16, threads: 1, offline: ""             },
		{ name: "4/2/10/2",
			packages: 4, nodes: 2, cores: 10, threads: 2, offline: ""             },
		{ name: "2/8/4",
			packages: 2,           cores:  8, threads: 4, offline: ""             },
		{ name: "2/8/4,-1-5",
			packages: 2,           cores:  8, threads: 4, offline: "1-5"          } } {
				topologies[topology.name] = topology
			}

	tests := []simpleAllocTest{}
	for _, test := range []simpleAllocTest{
		{ config: "2/10/2",
			alloc:   []int{ 20, 6, 4, 2, 1 },
			acheck:  []string{ "0-19", "20-22,30-32", "23-24,33-34", "25,35", "26" },
			release: []int{ 8, 2, 3, 1, 1 },
			rcheck:  []string{ "0-5,10-15", "20-21,30-31", "23", "25", "" } },
		{ config: "1/16/1",
			alloc:   []int{ 4, 2, 1 },
			acheck:  []string{ "0-3", "4-5", "6" },
			release: []int{ 2, 1, 1 },
			rcheck:  []string{ "0-1", "4", "" } },
		{ config: "4/2/10/2",
			alloc:   []int{ 1, 2, 4, 10, 8 },
			acheck:  []string{ "0", "1,11", "2-3,12-13", "4-8,14-18", "9,19-22,30-32" },
			release: []int{ 1, 1, 3, 4, 4, },
			rcheck:  []string{ "", "1", "2", "4-6,14-16", "9,19-20,30" } },
		{ config: "2/8/4",
			alloc:   []int{ 5, 8, 7, 1 },
			acheck:  []string{ "0-1,8,16,24", "2-3,10-11,18-19,26-27", "9,17,25,4,12,20,28", "5" },
			release: []int{ 1, 4, 3, 1 },
			rcheck:  []string{ "0,8,16,24", "2,10,18,26", "4,12,20,28", "" } },
		{ config: "2/8/4,-1-5",
			alloc:   []int{ 5, 8, 7, 1 },
			acheck:  []string{ "0,8-9,16,24", "6-7,14-15,22-23,30-31", "10,17,25,32,40,48,56", "18" },
			release: []int{ 1, 4, 3, 1 },
			rcheck:  []string{ "0,8,16,24", "6,14,22,30", "32,40,48,56", "" } } } {
				topology, ok := topologies[test.config]
				if !ok {
					t.Errorf("cannot find topology %s for test %+v", test.config, test)
					return
				}
				if len(test.alloc) != len(test.acheck) {
					t.Errorf("invalid test, alloc/check size mismatch: %+v", test)
					return
				}
				if len(test.release) != len(test.rcheck) {
					t.Errorf("invalid test, release/check size mismatch: %+v", test)
					return
				}

				test.topology = topology
				tests = append(tests, test)
			}

	for _, test := range tests {
		if err := runSimpleAllocTest(&test, t); err != nil {
			t.Errorf("%s", err)
			return
		}
	}
}
