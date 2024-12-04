// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"unique"

	"github.com/cilium/statedb/index"
)

const namespaceSeparator = "/"

// Name of a Kubernetes object.
type Name struct{ unique.Handle[nameInstance] }

// nameInstance stores the namespace and name as a concatenated string
// to avoid separate allocations for the namespace and the name. The
// position of the name is stored for quick access.
type nameInstance struct {
	namespacedName string
	namePos        int
}

func NewNamespacedName(namespace, name string) Name {
	if namespace == "" {
		return NewName(name)
	}
	return Name{
		unique.Make(nameInstance{
			namespacedName: namespace + namespaceSeparator + name,
			namePos:        len(namespace) + 1,
		}),
	}
}

func NewName(name string) Name {
	return Name{unique.Make(nameInstance{namespacedName: name, namePos: 0})}
}

func (n Name) String() string {
	return n.Value().namespacedName
}

func (n Name) Namespace() string {
	inst := n.Value()
	if inst.namePos == 0 {
		return ""
	}
	return inst.namespacedName[:inst.namePos-1]
}

func (n Name) Name() string {
	inst := n.Value()
	return inst.namespacedName[inst.namePos:]
}

func (n Name) Equal(other Name) bool {
	return n.Handle == other.Handle
}

func (n Name) Key() index.Key {
	return index.String(n.String())
}
