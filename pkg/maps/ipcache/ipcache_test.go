// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"fmt"
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
)

var (
	ipaddr   = "10.0.0.1"
	ipaddr2  = "2.2.2.2"
	identity = 2
)

func TestRemoteEndpointInfoFlagsStringReturnsCorrectValue(t *testing.T) {
	type stringTest struct {
		name string
		in   RemoteEndpointInfoFlags
		out  string
	}

	tests := []stringTest{
		{
			name: "no flags",
			in:   0,
			out:  "<none>",
		},
		{
			name: "FlagSkipTunnel",
			in:   FlagSkipTunnel,
			out:  "skiptunnel",
		},
	}

	for _, test := range tests {
		if s := test.in.String(); s != test.out {
			t.Errorf(
				"Expected '%s' for string representation of %s, instead got '%s'",
				test.out, test.name, s,
			)
		}
	}
}

func setup(tb testing.TB) *bpf.Map {
	testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS("")

	err := rlimit.RemoveMemlock()
	require.NoError(tb, err)

	testMap := newIPCacheMap(Name)

	err = testMap.OpenOrCreate()
	require.NoError(tb, err, "Failed to create map")

	// Add the key to the map
	mask := net.CIDRMask(32, 32)
	key := NewKey(net.ParseIP(ipaddr), mask, 0)
	err = testMap.Update(&key, &RemoteEndpointInfo{
		SecurityIdentity: uint32(identity),
	})
	require.NoError(tb, err)

	tb.Cleanup(func() {
		require.NoError(tb, testMap.Close())
	})

	return testMap
}

func TestLoadMap(t *testing.T) {
	testutils.PrivilegedTest(t)

	setup(t)

	tests := []struct {
		name          string
		expectedError error
	}{
		{
			name:          "Load map",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadMap()
			require.Equal(t, tt.expectedError, err)
		})
	}
}

func TestGet(t *testing.T) {
	setup(t)

	tests := []struct {
		name          string
		key           Key
		output        RemoteEndpointInfo
		expectedError error
	}{
		{
			name: "Successfully found in map",
			key:  NewKey(net.ParseIP(ipaddr), net.CIDRMask(32, 32), 0),
			output: RemoteEndpointInfo{
				SecurityIdentity: uint32(identity),
			},
			expectedError: nil,
		},
		{
			name:          "Failure to find in map",
			key:           NewKey(net.ParseIP(ipaddr2), net.CIDRMask(32, 32), 0),
			output:        RemoteEndpointInfo{},
			expectedError: fmt.Errorf("lookup: key does not exist"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := LoadMap()
			require.NoError(t, err)

			val, err := m.Get(tt.key)
			if tt.expectedError != nil {
				require.Equal(t, tt.expectedError.Error(), err.Error())
				require.Equal(t, tt.output, val)
				return
			}
			require.Equal(t, tt.expectedError, err)
			require.Equal(t, tt.output.SecurityIdentity, val.SecurityIdentity)
		})
	}
}
