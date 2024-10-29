// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/k8s"
)

func TestName(t *testing.T) {
	testCases := []struct {
		namespace string
		name      string
		str       string
	}{
		{"", "foo", "foo"},
		{"foo", "bar", "foo/bar"},
		{"", "", ""},
	}

	for _, tc := range testCases {
		n := k8s.NewNamespacedName(tc.namespace, tc.name)
		require.Equal(t, tc.namespace, n.Namespace())
		require.Equal(t, tc.name, n.Name())
		require.Equal(t, tc.str, n.String())
		require.Equal(t, tc.str, string(n.Key()))
		n2 := k8s.NewNamespacedName(strings.Clone(tc.namespace), strings.Clone(tc.name))
		require.True(t, n.Equal(n2))
		require.Equal(t, n.String(), n2.String())
		require.Equal(t, n.Key(), n2.Key())
	}
}
