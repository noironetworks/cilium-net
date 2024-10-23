// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/duration"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

// LocalPod is Cilium's internal model of the pods running on this node.
type LocalPod struct {
	*slim_corev1.Pod

	UpdatedAt time.Time
}

func (p LocalPod) TableHeader() []string {
	return []string{
		"Name",
		"HostNetwork",
		"PodIPs",
		"Containers",
		"Phase",
		"Age",
	}
}

func (p LocalPod) TableRow() []string {
	var podIPs []string
	for _, ip := range p.Status.PodIPs {
		podIPs = append(podIPs, ip.IP)
	}
	var containers []string
	for _, cont := range p.Spec.Containers {
		var ports []string
		for _, port := range cont.Ports {
			if port.Name != "" {
				ports = append(ports, fmt.Sprintf("%d/%s (%s)", port.ContainerPort, string(port.Protocol), port.Name))
			} else {
				ports = append(ports, fmt.Sprintf("%d/%s", port.ContainerPort, string(port.Protocol)))
			}
		}
		contName := cont.Name
		if len(ports) > 0 {
			contName += " (" + strings.Join(ports, ",") + ")"
		}
		containers = append(containers, contName)
	}
	return []string{
		p.Namespace + "/" + p.Name,
		strconv.FormatBool(p.Spec.HostNetwork),
		strings.Join(podIPs, ", "),
		strings.Join(containers, ", "),
		string(p.Status.Phase),
		duration.HumanDuration(time.Since(p.UpdatedAt)),
	}
}

const (
	PodTableName = "k8s-pods"
)

var (
	PodNameIndex = newNameIndex[LocalPod]()

	PodTableCell = cell.Group(
		cell.ProvidePrivate(NewPodTable),
		cell.Provide(statedb.RWTable[LocalPod].ToTable),
		cell.Invoke(registerPodReflector),
	)
)

func PodByName(namespace, name string) statedb.Query[LocalPod] {
	return PodNameIndex.Query(k8s.NewNamespacedName(namespace, name))
}

func NewPodTable(db *statedb.DB) (statedb.RWTable[LocalPod], error) {
	tbl, err := statedb.NewTable(
		PodTableName,
		PodNameIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

func registerPodReflector(jg job.Group, db *statedb.DB, cs client.Clientset, pods statedb.RWTable[LocalPod]) error {
	if !cs.IsEnabled() {
		return nil
	}
	cfg := podReflectorConfig(cs, pods)
	return k8s.RegisterReflector(jg, db, cfg)
}

func podReflectorConfig(cs client.Clientset, pods statedb.RWTable[LocalPod]) k8s.ReflectorConfig[LocalPod] {
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped(cs.Slim().CoreV1().Pods("")),
		func(opts *metav1.ListOptions) {
			opts.FieldSelector = fields.ParseSelectorOrDie("spec.nodeName=" + nodeTypes.GetName()).String()
		})
	return k8s.ReflectorConfig[LocalPod]{
		Name:          "daemon",
		Table:         pods,
		ListerWatcher: lw,
		Transform: func(_ statedb.ReadTxn, obj any) (LocalPod, bool) {
			pod, ok := obj.(*slim_corev1.Pod)
			if !ok {
				return LocalPod{}, false
			}
			return LocalPod{
				Pod:       pod,
				UpdatedAt: time.Now(),
			}, true
		},
	}
}
