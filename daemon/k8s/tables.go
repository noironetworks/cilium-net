// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/k8s"
)

// ResourcesCell provides a set of handles to Kubernetes resources used throughout the
// agent. Each of the resources share a client-go informer and backing store so we only
// have one watch API call for each resource kind and that we maintain only one copy of each object.
//
// See pkg/k8s/resource/resource.go for documentation on the Resource[T] type.

// TablesCell provides a set of StateDB tables for common Kubernetes objects.
// The tables are populated with the StateDB k8s reflector (pkg/k8s/statedb.go).
// Some tables are provided as OnDemand[Table[T]]
var TablesCell = cell.Module(
	"k8s-tables",
	"StateDB tables of Kubernetes objects",

	PodTableCell,
)

func newNameIndex[Obj metav1.Object]() statedb.Index[Obj, k8s.Name] {
	return statedb.Index[Obj, k8s.Name]{
		Name: "name",
		FromObject: func(obj Obj) index.KeySet {
			return index.NewKeySet(index.Stringer(k8s.NewNamespacedName(obj.GetNamespace(), obj.GetName())))
		},
		FromKey: index.Stringer[k8s.Name],
		FromString: func(key string) (index.Key, error) {
			return index.String(key), nil
		},
		Unique: true,
	}
}
