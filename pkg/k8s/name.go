// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"strings"
	"unique"

	"github.com/cilium/statedb/index"
)

const namespaceSeparator = "/"

// Name of a Kubernetes object.
type Name struct{ unique.Handle[string] }

func NewNamespacedName(namespace, name string) Name {
	if namespace == "" {
		return NewName(name)
	}
	return Name{
		unique.Make(namespace + namespaceSeparator + name),
	}
}

func NewName(name string) Name {
	return Name{unique.Make(name)}
}

func (n Name) String() string {
	return n.Value()
}

func (n Name) Namespace() string {
	ns, _, found := strings.Cut(n.Value(), namespaceSeparator)
	if found {
		return ns
	}
	return ""
}

func (n Name) Name() string {
	_, name, found := strings.Cut(n.Value(), namespaceSeparator)
	if found {
		return name
	}
	return n.Value()
}

func (n Name) Equal(other Name) bool {
	return n.Handle == other.Handle
}

func (n Name) Key() index.Key {
	return index.String(n.String())
}
