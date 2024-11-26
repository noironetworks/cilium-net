package maps

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
)

func setup(t *testing.T) *bpf.Map {
	// testutils.PrivilegedTest(tb)

	bpf.CheckOrMountFS("")

	err := rlimit.RemoveMemlock()
	require.NoError(t, err)

	testMap := bpf.NewMap(
		ipcache.Name,
		ebpf.LPMTrie,
		&ipcache.Key{},
		&ipcache.RemoteEndpointInfo{},
		10,
		bpf.BPF_F_NO_PREALLOC)

	err = testMap.OpenOrCreate()
	require.NoError(t, err, "Failed to create map")

	// Add the key to the map
	mask := net.CIDRMask(32, 32)
	key := ipcache.NewKey(net.ParseIP("192.168.1.1"), mask, 0)
	err = testMap.Update(&key, &ipcache.RemoteEndpointInfo{
		SecurityIdentity: uint32(1),
	})
	require.NoError(t, err)

	// Add the key to the map
	mask = net.CIDRMask(128, 128)
	key = ipcache.NewKey(net.ParseIP("2001:db8::1"), mask, 0)
	err = testMap.Update(&key, &ipcache.RemoteEndpointInfo{
		SecurityIdentity: uint32(2),
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, testMap.Close())
	})

	return testMap
}

func TestGetIdentity(t *testing.T) {
	_ = setup(t)
	tests := []struct {
		name          string
		ipAddr        netip.Addr
		expectedInfo  ipcache.RemoteEndpointInfo
		expectedError error
	}{
		{
			name:          "IPv4 address",
			ipAddr:        netip.MustParseAddr("192.168.1.1"),
			expectedInfo:  ipcache.RemoteEndpointInfo{SecurityIdentity: 1},
			expectedError: nil,
		},
		{
			name:          "IPv6 address",
			ipAddr:        netip.MustParseAddr("2001:db8::1"),
			expectedInfo:  ipcache.RemoteEndpointInfo{SecurityIdentity: 2},
			expectedError: nil,
		},
		{
			name:          "Get error",
			ipAddr:        netip.MustParseAddr("192.168.1.0"),
			expectedInfo:  ipcache.RemoteEndpointInfo{},
			expectedError: fmt.Errorf("lookup: key does not exist"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := GetIdentity(tt.ipAddr)
			require.Equal(t, tt.expectedInfo, info)
			if err == nil {
				require.Equal(t, tt.expectedError, err)
			} else {
				require.Equal(t, tt.expectedError.Error(), err.Error())
			}
		})
	}
}
