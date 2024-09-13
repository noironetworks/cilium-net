// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package v2

import (
	"context"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	scheme "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// CiliumNodeConfigsGetter has a method to return a CiliumNodeConfigInterface.
// A group's client should implement this interface.
type CiliumNodeConfigsGetter interface {
	CiliumNodeConfigs(namespace string) CiliumNodeConfigInterface
}

// CiliumNodeConfigInterface has methods to work with CiliumNodeConfig resources.
type CiliumNodeConfigInterface interface {
	Create(ctx context.Context, ciliumNodeConfig *v2.CiliumNodeConfig, opts v1.CreateOptions) (*v2.CiliumNodeConfig, error)
	Update(ctx context.Context, ciliumNodeConfig *v2.CiliumNodeConfig, opts v1.UpdateOptions) (*v2.CiliumNodeConfig, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v2.CiliumNodeConfig, error)
	List(ctx context.Context, opts v1.ListOptions) (*v2.CiliumNodeConfigList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2.CiliumNodeConfig, err error)
	CiliumNodeConfigExpansion
}

// ciliumNodeConfigs implements CiliumNodeConfigInterface
type ciliumNodeConfigs struct {
	*gentype.ClientWithList[*v2.CiliumNodeConfig, *v2.CiliumNodeConfigList]
}

// newCiliumNodeConfigs returns a CiliumNodeConfigs
func newCiliumNodeConfigs(c *CiliumV2Client, namespace string) *ciliumNodeConfigs {
	return &ciliumNodeConfigs{
		gentype.NewClientWithList[*v2.CiliumNodeConfig, *v2.CiliumNodeConfigList](
			"ciliumnodeconfigs",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *v2.CiliumNodeConfig { return &v2.CiliumNodeConfig{} },
			func() *v2.CiliumNodeConfigList { return &v2.CiliumNodeConfigList{} }),
	}
}