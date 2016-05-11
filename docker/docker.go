// +build linux

/*
http://www.apache.org/licenses/LICENSE-2.0.txt


Copyright 2015 Intel Corporation

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

package docker

import (

	//"fmt"
	//"path/filepath"
	//"strings"

	//"github.com/opencontainers/runc/libcontainer/cgroups"
	dock "github.com/fsouza/go-dockerclient"

	//tls "github.com/intelsdi-x/snap-plugin-collector-docker/tools"
	//"github.com/intelsdi-x/snap-plugin-collector-docker/wrapper"
	"github.com/intelsdi-x/snap/control/plugin"
	"github.com/intelsdi-x/snap/control/plugin/cpolicy"
	//"github.com/intelsdi-x/snap/core"
	"fmt"
	"github.com/intelsdi-x/snap/core"
	"os"
	//"time"
	"github.com/intelsdi-x/snap-plugin-collector-docker/client"
	
)

const (
	// namespace vendor prefix
	NS_VENDOR = "intel"
	// namespace plugin name
	NS_PLUGIN = "docker"
	// version of plugin
	VERSION = 4
	// mount info
	mountInfo        = "/proc/self/mountinfo"
	endpoint  string = "unix:///var/run/docker.sock"
)

/*
// Docker plugin type
type docker struct {
	stats          *cgroups.Stats               // structure for stats storage
	client         client.DockerClientInterface // client for communication with docker (basic info, mount points)
	tools          tls.ToolsInterface           // tools for handling namespaces and processing stats
	containersInfo []client.ContainerInfo       // basic info about running containers
	groupWrap      map[string]wrapper.Stats     // wrapper for cgroup name and interface for stats extraction
	hostname       string                       // name of the host
	containerStats []*dock.Stats

}*/

var availableStats = [][]string{

	// docker specification info
	[]string{"spec", "creation_time"},

	//cpu stats
	[]string{"cpu", "usage", "total_usage"},
	[]string{"cpu", "usage", "usage_in_kernelmode"},
	[]string{"cpu", "usage", "usage_in_usermode"},

	[]string{"cpu", "throttling", "periods"},
	[]string{"cpu", "throttling", "throttled_periods"},
	[]string{"cpu", "throttling", "throttled_time"},

	//memory stats
	[]string{"memory", "total_usage"},
	[]string{"memory", "max_usage"},
	[]string{"memory", "failcnt"},
	[]string{"memory", "limit"},
	[]string{"memory", "cache"},
	[]string{"memory", "pgfault"},
	[]string{"memory", "pgmajfault"},

	//network stats
	[]string{"network", "rx_dropped"},
	[]string{"network", "rx_bytes"},
	[]string{"network", "rx_errors"},
	[]string{"network", "rx_packets"},
	[]string{"network", "tx_dropped"},
	[]string{"network", "tx_bytes"},
	[]string{"network", "tx_errors"},
	[]string{"network", "tx_packets"},
}

type containerData struct {
	id         string
	status     string
	created    int64
	image      string
	sizeRw     int64
	sizeRootFs int64       // basic info about the container (status, uptime, etc.)
	stats      *dock.Stats // container statistics (cpu usage, memory usage, network stats, etc.)
}

// docker collector plugin type
type docker struct {
	containers  map[string]containerData // holds data for a container under its short id
	initialized bool
	client      client.DockerClientInterface 	// client for communication with docker (basic info, stats, mount points)

	//tools          tls.ToolsInterface           // tools for handling namespaces and processing stats
	//containersInfo []client.ContainerInfo       // basic info about running containers
	//groupWrap      map[string]wrapper.Stats     // wrapper for cgroup name and interface for stats extraction
	//hostname       string                       // name of the host

}

// Docker plugin initializer
func New() *docker {

	//todo tworzenie new docker clinet w init!
	return &docker{
		containers:  map[string]containerData{},
		client: client.NewDockerClient(),
	}
}

/*
// wrapper for cgroup stats extraction
func (d *DockerCollector) getStats(id string) error {

	for cg, stat := range d.groupWrap {
		// find mount point for each cgroup
		mp, err := d.client.FindCgroupMountpoint(cg)

		if err != nil {
			fmt.Printf("[WARNING] Could not find mount point for %s\n", cg)
			continue
		}

		// create path to cgroup for given docker id
		groupPath := filepath.Join(mp, "docker", id)
		// get cgroup stats for given docker
		if err := stat.GetStats(groupPath, d.stats); err != nil {
			return err
		}
	}

	return nil
}
*/

// getShortId returns short version of container ID (12 char)
func getShortId(dockerID string) (string, error) {
	//todo dac sprawdzenie
	// get short version of container ID
	return dockerID[:12], nil
}

// getRequestedDockerIDs returns requested docker ids and boolean status which is set to true
// if all docker ids are requested by using wildcard as docker id in incoming metricType
func getRequestedDockerIDs(mts []plugin.MetricType) ([]string, bool) {
	rids := []string{}
	for _, mt := range mts {
		rid := mt.Namespace().Strings()[2]
		if rid == "*" {
			// all available dockers are requested
			return nil, true
		}
		shortid, _ := getShortId(rid)
		rids = appendIfMissing(rids, shortid)
	}
	return rids, false
}


func appendIfMissing(items []string, newItem string) []string {
	for _, item := range items {
		if newItem == item {
			// do not append new item
			return items
		}
	}
	return append(items, newItem)
}

/*
// getShortId returns short version of container ID (12 char)
func getShortId(dockerID string) (string, error) {
	//todo dac sprawdzenie
	// get short version of container ID
	return dockerID[:12], nil
}
*/

func (d *docker) CollectMetrics(mts []plugin.MetricType) ([]plugin.MetricType, error) {
	metrics := []plugin.MetricType{}

	// list all running containers
	containerList, err := d.client.ListContainersAsMap()
	if err != nil {
		fmt.Fprintln(os.Stderr, "The list of running containers cannot be retrived, err=%+v", err)
		return nil, err
	}

	// retrieve requested docker ids
	rids, all := getRequestedDockerIDs(mts)

	if all {
		// add all available docker containers IDs as requested
		for id, _ := range containerList {
			rids = append(rids, id)
		}
	}


	// for each requested id set adequate item into docker.container struct
	for _, rid := range rids {

		if contSpec, exist := containerList[rid]; exist {
			// set new item to docker.container structure
			d.containers[rid] = containerData{
				id:         contSpec.ID,
				status:     contSpec.Status,
				created:    contSpec.Created,
				image:      contSpec.Image,
				sizeRw:     contSpec.SizeRw,
				sizeRootFs: contSpec.SizeRootFs,
				stats:      new(dock.Stats),
			}

		} else {
			return nil, fmt.Errorf("Docker container does not exist, container_id=", rid)
		}


		stats, err := d.client.GetContainerStats(rid, 0)
		if err != nil {
			return nil, err
		}
		*d.containers[rid].stats = *stats
	}





/*
	//tutaj wpisanie danych do metrykTypes
	id, _ := getShortId(containers[0].ID)
	switch mts[0].Namespace().Strings()[3] {
	case "cpu":
		fmt.Fprintln(os.Stderr, "CPU metrics")
		fmt.Fprintln(os.Stderr, "CPU metrics, total usage= %+v", d.containers[id].stats.CPUStats.CPUUsage.TotalUsage)
		fmt.Fprintln(os.Stderr, "CPU metrics")
		ns := core.NewNamespace(NS_VENDOR, NS_PLUGIN, id, "usage", "total_usage")

		metric := plugin.MetricType{
			Namespace_: ns,
			Data_:      d.containers[id].stats.CPUStats.CPUUsage.TotalUsage,
			Timestamp_: time.Now(),
		}
		metrics = append(metrics, metric)

	case "memory":
		fmt.Fprintln(os.Stderr, "Memory metrics")
	case "network":
		fmt.Fprintln(os.Stderr, "Network metrics")
	case "spec":
		fmt.Fprintln(os.Stderr, "spec metrics")
	default:
		fmt.Fprintln(os.Stderr, "Error: unrecognize metric type %+v", mts[0].Namespace().Strings())
		return nil, errors.New("unrecognize metric type")
	}

	fmt.Fprintf(os.Stderr, "Debug, iza zebrane statystyki memory: %+s", d.containers[id].stats.MemoryStats)
	fmt.Fprintf(os.Stderr, "/n/n")
	fmt.Fprintf(os.Stderr, "Debug, iza zebrane statystyki cpu: %+s", d.containers[id].stats.CPUStats)
	//todo iza tymczasowo
	//resultStats = append(resultStats, stats)
*/
	return metrics, nil
}

func (d *docker) GetMetricTypes(_ plugin.ConfigType) ([]plugin.MetricType, error) {
	//var namespaces []string
	var metricTypes []plugin.MetricType

	//d.init()

	// try to list all running containers to check docker client conn
	if _, err := d.client.ListContainersAsMap(); err != nil {
		fmt.Fprintln(os.Stderr, "The list of running containers cannot be retrived, err=%+v", err)
		return nil, err
	}


	// list of metrics
	for _, statName := range availableStats {

		ns := core.NewNamespace(NS_VENDOR, NS_PLUGIN).
			AddDynamicElement("docker_id", "id of docker container").
			AddStaticElements(statName...)

		metricType := plugin.MetricType{
			Namespace_: ns,
		}

		metricTypes = append(metricTypes, metricType)
	}

	return metricTypes, nil

	/*


		for _, cont := range containers {
			//todo obsługa błedu
			dockerShortID, _ := getShortId(cont.Id)

			d.containers[dockerShortID] = containerData{
				id: 		cont.Id,
				status: 	cont.Status,
				created: 	cont.Created,
				image: 		cont.Image,
				sizeRw: 	cont.SizeRw,
				sizeRootFs: 	cont.SizeRootFs,
				stats: 		new(dock.Stats),
			}


			fmt.Fprint(os.Stderr, " Debug, container id=", cont.Id)
			fmt.Fprint(os.Stderr, " Debug, container data=", d.containers[cont.Id])
		}

		//todo do przerzucenia później


		cl, err := dock.NewClient(endpoint)
		if err != nil {
			fmt.Println("[ERROR] Could not create docker client!")
			return nil, err
		}

		errChan := make(chan error, 1)
		statsChan := make(chan *dock.Stats)
		done := make(chan bool)

		id := containers[0].Id
		go func() {
			//todo container id tymczasowo
			errChan <- cl.Stats(dock.StatsOptions{id, statsChan, true, done, 0})
			close(errChan)
		}()

		for {
			stats, ok := <-statsChan

			if !ok {
				break
			}

			//set stats

			fmt.Fprintf(os.Stderr, "Debug, izaPRZED zebrane statystyki memory: %+s", stats.MemoryStats)
			fmt.Fprintf(os.Stderr, "/n/n")
			fmt.Fprintf(os.Stderr, "Debug, izaPRZED zebrane statystyki cpu: %+s", stats.CPUStats)

			*d.containers[id].stats = *stats
			fmt.Fprintf(os.Stderr, "stats=", stats)
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintf(os.Stderr, "Debug, iza zebrane statystyki memory: %+s", d.containers[id].stats.MemoryStats)
			fmt.Fprintf(os.Stderr, "/n/n")
			fmt.Fprintf(os.Stderr, "Debug, iza zebrane statystyki cpu: %+s", d.containers[id].stats.CPUStats)
			//todo iza tymczasowo
			//resultStats = append(resultStats, stats)
		}
		err = <-errChan
		if err != nil {
			return nil, err
		}

	*/

	/*		//todo czy to jest potyrzebne
	// list all running containers
	_, err := dockerClient.ListContainers()

	if err != nil {
		return nil, err
	}

	for _, container := range d.containersInfo {
		// calling getStats will populate stats object
		// parsing it one will get info on available namespace
		d.getStats(container.Id)

		// marshal-unmarshal to get map with json tags as keys
		jsondata, _ := json.Marshal(d.stats)
		var jmap map[string]interface{}
		json.Unmarshal(jsondata, &jmap)

		// parse map to get namespace strings
		d.tools.Map2Namespace(jmap, container.Id[:12], &namespaces)
	}

	// wildcard for container ID
	if len(d.containersInfo) > 0 {
		jsondata, _ := json.Marshal(d.stats)
		var jmap map[string]interface{}
		json.Unmarshal(jsondata, &jmap)
		d.tools.Map2Namespace(jmap, "*", &namespaces)
	}

	for _, namespace := range namespaces {
		// construct full namespace
		fullNs := filepath.Join(NS_VENDOR, NS_PLUGIN, namespace)
		metricTypes = append(metricTypes, plugin.MetricType{Namespace_: core.NewNamespace(strings.Split(fullNs, "/")...)})
	}
	*/

	return metricTypes, nil
}

func (d *docker) GetConfigPolicy() (*cpolicy.ConfigPolicy, error) {
	return cpolicy.New(), nil
}
