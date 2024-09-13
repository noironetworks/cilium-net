// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeCiliumBGPNodeConfigs implements CiliumBGPNodeConfigInterface
type FakeCiliumBGPNodeConfigs struct {
	Fake *FakeCiliumV2alpha1
}

var ciliumbgpnodeconfigsResource = v2alpha1.SchemeGroupVersion.WithResource("ciliumbgpnodeconfigs")

var ciliumbgpnodeconfigsKind = v2alpha1.SchemeGroupVersion.WithKind("CiliumBGPNodeConfig")

// Get takes name of the ciliumBGPNodeConfig, and returns the corresponding ciliumBGPNodeConfig object, and an error if there is any.
func (c *FakeCiliumBGPNodeConfigs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v2alpha1.CiliumBGPNodeConfig, err error) {
	emptyResult := &v2alpha1.CiliumBGPNodeConfig{}
	obj, err := c.Fake.
		Invokes(testing.NewRootGetActionWithOptions(ciliumbgpnodeconfigsResource, name, options), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v2alpha1.CiliumBGPNodeConfig), err
}

// List takes label and field selectors, and returns the list of CiliumBGPNodeConfigs that match those selectors.
func (c *FakeCiliumBGPNodeConfigs) List(ctx context.Context, opts v1.ListOptions) (result *v2alpha1.CiliumBGPNodeConfigList, err error) {
	emptyResult := &v2alpha1.CiliumBGPNodeConfigList{}
	obj, err := c.Fake.
		Invokes(testing.NewRootListActionWithOptions(ciliumbgpnodeconfigsResource, ciliumbgpnodeconfigsKind, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v2alpha1.CiliumBGPNodeConfigList{ListMeta: obj.(*v2alpha1.CiliumBGPNodeConfigList).ListMeta}
	for _, item := range obj.(*v2alpha1.CiliumBGPNodeConfigList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested ciliumBGPNodeConfigs.
func (c *FakeCiliumBGPNodeConfigs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchActionWithOptions(ciliumbgpnodeconfigsResource, opts))
}

// Create takes the representation of a ciliumBGPNodeConfig and creates it.  Returns the server's representation of the ciliumBGPNodeConfig, and an error, if there is any.
func (c *FakeCiliumBGPNodeConfigs) Create(ctx context.Context, ciliumBGPNodeConfig *v2alpha1.CiliumBGPNodeConfig, opts v1.CreateOptions) (result *v2alpha1.CiliumBGPNodeConfig, err error) {
	emptyResult := &v2alpha1.CiliumBGPNodeConfig{}
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateActionWithOptions(ciliumbgpnodeconfigsResource, ciliumBGPNodeConfig, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v2alpha1.CiliumBGPNodeConfig), err
}

// Update takes the representation of a ciliumBGPNodeConfig and updates it. Returns the server's representation of the ciliumBGPNodeConfig, and an error, if there is any.
func (c *FakeCiliumBGPNodeConfigs) Update(ctx context.Context, ciliumBGPNodeConfig *v2alpha1.CiliumBGPNodeConfig, opts v1.UpdateOptions) (result *v2alpha1.CiliumBGPNodeConfig, err error) {
	emptyResult := &v2alpha1.CiliumBGPNodeConfig{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateActionWithOptions(ciliumbgpnodeconfigsResource, ciliumBGPNodeConfig, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v2alpha1.CiliumBGPNodeConfig), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeCiliumBGPNodeConfigs) UpdateStatus(ctx context.Context, ciliumBGPNodeConfig *v2alpha1.CiliumBGPNodeConfig, opts v1.UpdateOptions) (result *v2alpha1.CiliumBGPNodeConfig, err error) {
	emptyResult := &v2alpha1.CiliumBGPNodeConfig{}
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceActionWithOptions(ciliumbgpnodeconfigsResource, "status", ciliumBGPNodeConfig, opts), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v2alpha1.CiliumBGPNodeConfig), err
}

// Delete takes name of the ciliumBGPNodeConfig and deletes it. Returns an error if one occurs.
func (c *FakeCiliumBGPNodeConfigs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(ciliumbgpnodeconfigsResource, name, opts), &v2alpha1.CiliumBGPNodeConfig{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeCiliumBGPNodeConfigs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionActionWithOptions(ciliumbgpnodeconfigsResource, opts, listOpts)

	_, err := c.Fake.Invokes(action, &v2alpha1.CiliumBGPNodeConfigList{})
	return err
}

// Patch applies the patch and returns the patched ciliumBGPNodeConfig.
func (c *FakeCiliumBGPNodeConfigs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2alpha1.CiliumBGPNodeConfig, err error) {
	emptyResult := &v2alpha1.CiliumBGPNodeConfig{}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceActionWithOptions(ciliumbgpnodeconfigsResource, name, pt, data, opts, subresources...), emptyResult)
	if obj == nil {
		return emptyResult, err
	}
	return obj.(*v2alpha1.CiliumBGPNodeConfig), err
}