// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// NodeLister helps list Nodes.
// All objects returned here must be treated as read-only.
type NodeLister interface {
	// List lists all Nodes in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.Node, err error)
	// Get retrieves the Node from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.Node, error)
	NodeListerExpansion
}

// nodeLister implements the NodeLister interface.
type nodeLister struct {
	listers.ResourceIndexer[*v1.Node]
}

// NewNodeLister returns a new NodeLister.
func NewNodeLister(indexer cache.Indexer) NodeLister {
	return &nodeLister{listers.New[*v1.Node](indexer, v1.Resource("node"))}
}