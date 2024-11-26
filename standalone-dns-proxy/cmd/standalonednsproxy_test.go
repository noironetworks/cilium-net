package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	standalonednsproxy "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
	ipcachePkg "github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/trigger"
	"github.com/cilium/dns"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestNewStandaloneDNSProxy(t *testing.T) {
	tests := []struct {
		name string
		args *StandaloneDNSProxyArgs
		err  error
	}{
		{
			name: "Valid grpc server port",
			args: &StandaloneDNSProxyArgs{
				toFqdnServerPort: 1234,
				enableL7Proxy:    true,
			},
			err: nil,
		},
		{
			name: "Invalid grpc server port",
			args: &StandaloneDNSProxyArgs{
				toFqdnServerPort: 0,
				enableL7Proxy:    true,
			},
			err: errors.New("toFqdnServerPort is 0"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sdp, err := NewStandaloneDNSProxy(tt.args)
			if err != nil {
				require.Equal(t, tt.err, err)
				return
			}
			require.Nil(t, err)
			require.NotNil(t, sdp)
		})
	}
}

func TestStandaloneDNSProxyWhenDisabled(t *testing.T) {
	test := map[string]struct {
		args *StandaloneDNSProxyArgs
		err  error
	}{
		"L7ProxyDisbaled": {
			args: &StandaloneDNSProxyArgs{
				toFqdnServerPort:         4321,
				enableStandaloneDNsProxy: false,
				enableL7Proxy:            false,
			},
			err: nil,
		},
		"StandaloneDNSProxyDisabled": {
			args: &StandaloneDNSProxyArgs{
				toFqdnServerPort:         4321,
				enableStandaloneDNsProxy: false,
				enableL7Proxy:            true,
			},
			err: nil,
		},
	}

	for name, tt := range test {
		t.Run(name, func(t *testing.T) {
			sdp, err := NewStandaloneDNSProxy(tt.args)
			require.NoError(t, err)
			require.Nil(t, sdp.DNSProxy)
		})
	}
}

func TestStandaloneDNSProxyWhenEnabled(t *testing.T) {
	testutils.PrivilegedTest(t)

	sdp, err := NewStandaloneDNSProxy(&StandaloneDNSProxyArgs{
		DNSProxyConfig: dnsproxy.DNSProxyConfig{
			Address:                "",
			Port:                   1234,
			IPv4:                   true,
			IPv6:                   true,
			EnableDNSCompression:   true,
			MaxRestoreDNSIPs:       10,
			ConcurrencyLimit:       10,
			ConcurrencyGracePeriod: 10,
			DNSProxyType:           dnsproxy.StandaloneDNSProxy,
		},
		toFqdnServerPort:         4321,
		enableStandaloneDNsProxy: true,
		enableL7Proxy:            true,
	})
	require.NoError(t, err)

	sdp.StartStandaloneDNSProxy()
	defer sdp.StopStandaloneDNSProxy()

	// check if the server is running
	require.Equal(t, dnsproxy.StandaloneDNSProxy, sdp.DNSProxy.DNSProxyType)
	require.NotNil(t, sdp.ciliumAgentConnectionTrigger)
}

type MockFQDNDataServer struct {
	standalonednsproxy.UnimplementedFQDNDataServer
}

func (m *MockFQDNDataServer) UpdatesMappings(ctx context.Context, in *standalonednsproxy.FQDNMapping) (*standalonednsproxy.UpdatesMappingsResult, error) {
	return &standalonednsproxy.UpdatesMappingsResult{
		Success: true,
	}, nil
}

// create a channel to receive the DNS rules
var dnsPoliciesResult = make(chan *standalonednsproxy.DNSPoliciesResult)

func (m *MockFQDNDataServer) SubscribeToDNSPolicies(stream standalonednsproxy.FQDNData_SubscribeToDNSPoliciesServer) error {
	//Send the current state of the DNS rules
	go func() {
		res, err := stream.Recv()
		if err != nil {
			log.Errorf("Error receiving DNS rules: %v", err)
		}
		fmt.Printf("Received DNS rules: %v", res)
		dnsPoliciesResult <- res
		fmt.Printf("Sent DNS rules: %v", res)
		// Send the close message
		stream.Context().Done()
	}()
	go func() {
		// Send the current state of the DNS rules
		err := stream.Send(&standalonednsproxy.DNSPolicies{
			EgressL7DnsPolicy: []*standalonednsproxy.DNSPolicy{
				{
					SourceIdentity: 1,
					DnsPattern:     []string{"*.cilium.io", "example.com"},
					DnsServers: []*standalonednsproxy.DNSServer{
						{
							DnsServerIdentity: 2,
							DnsServerPort:     53,
							DnsServerProto:    17,
						},
					},
				},
			},
			RequestId: "1",
		})
		if err != nil {
			log.Errorf("Error sending DNS rules: %v", err)
		}
	}()

	log.Debugf("SubscribeToDNSPolicies waiting for context to be done")
	<-stream.Context().Done()
	log.Info("Closing the stream")
	return stream.Context().Err()
}

func setupStandaloneDNSProxy(t *testing.T, ctx context.Context) (*StandaloneDNSProxy, func()) {
	buffer := 1024
	lis := bufconn.Listen(buffer)

	baseServer := grpc.NewServer()

	server := &MockFQDNDataServer{}
	standalonednsproxy.RegisterFQDNDataServer(baseServer, server)
	go func() {
		if err := baseServer.Serve(lis); err != nil {
			log.Fatalf("Server exited with error: %v", err)
		}
	}()

	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))

	if err != nil {
		log.Fatalf("Failed to dial bufnet: %v", err)
	}

	sdp, err := NewStandaloneDNSProxy(&StandaloneDNSProxyArgs{
		DNSProxyConfig: dnsproxy.DNSProxyConfig{
			Address: "",
			Port:    1234,
			IPv4:    true,
			IPv6:    false,
		},
		toFqdnServerPort:         4321,
		enableStandaloneDNsProxy: true,
		enableL7Proxy:            true,
	})
	require.NoError(t, err)

	sdp.connection = conn

	closer := func() {
		if sdp.Client != nil {
			sdp.connection.Close()
		}
		err := lis.Close()
		if err != nil {
			log.Printf("error closing listener: %v", err)
		}
		baseServer.Stop()
	}

	return sdp, closer
}

func TestSubscribeToDNSRules(t *testing.T) {
	testutils.PrivilegedTest(t)

	sdp, closer := setupStandaloneDNSProxy(t, context.Background())
	defer closer()

	// Create the client
	err := sdp.CreateClient(context.Background())
	require.NoError(t, err)
	tr, err := trigger.NewTrigger(trigger.Parameters{
		TriggerFunc: func(reasons []string) {
			time.Sleep(time.Second)
		},
	})
	require.NoError(t, err)
	sdp.ciliumAgentConnectionTrigger = tr
	// Add a dummy dns proxy server
	sdp.DNSProxy, err = dnsproxy.StartDNSProxy(sdp.args.DNSProxyConfig, // any address, any port, enable ipv4, enable ipv6, enable compression, max 1000 restore IPs
		// LookupEPByIP
		func(ip netip.Addr) (*endpoint.Endpoint, bool, error) {
			return &endpoint.Endpoint{}, false, nil
		},
		// LookupSecIDByIP
		func(ip netip.Addr) (ipcachePkg.Identity, bool) {
			return ipcachePkg.Identity{}, false
		},
		// LookupIPsBySecID
		func(nid identity.NumericIdentity) []string {
			return []string{}
		},
		// NotifyOnDNSMsg
		func(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, dstAddr string, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
			return nil
		},
	)
	require.NoError(t, err)
	// SubscribeToDNSRules is called successfully
	go func() {
		context, cancel := context.WithCancel(context.Background())
		sdp.cancelSubscribeToDNSRules = cancel
		err = sdp.subscribeToDNSRules(context)
		require.Contains(t, err.Error(), "rpc error: code = Canceled desc = grpc: the client connection is closing")
	}()
	// check if the server received the success or not
	result := <-dnsPoliciesResult
	require.True(t, result.GetSuccess())

	// // check the dnsResult channel is empty
	select {
	case <-dnsPoliciesResult:
		t.Fatalf("dnsPoliciesResult channel is not empty")
	default:
		log.Info("dnsPoliciesResult channel is empty")
	}
}

func TestCreateClientIsCreatedSuccessfully(t *testing.T) {
	ctx := context.Background()
	sdp, closer := setupStandaloneDNSProxy(t, ctx)
	defer closer()

	err := sdp.CreateClient(ctx)
	require.NoError(t, err)

	// check if the client is created
	require.NotNil(t, sdp.Client)
	// Check if dns rules stream is created
	require.NotNil(t, sdp.dnsRulesStream)
}

func TestCreateClientFails(t *testing.T) {
	ctx := context.Background()
	sdp, closer := setupStandaloneDNSProxy(t, ctx)
	defer closer()

	sdp.connection = nil
	err := sdp.CreateClient(ctx)
	require.Error(t, err)
}

func TestNotifyOnDNSMsg(t *testing.T) {
	ctx := context.Background()
	sdp, closer := setupStandaloneDNSProxy(t, ctx)
	defer closer()

	err := sdp.CreateClient(ctx)
	require.NoError(t, err)

	ep := &endpoint.Endpoint{
		SecurityIdentity: &identity.Identity{
			ID: 1,
		},
	}
	serverId := identity.NumericIdentity(2)
	msg := new(dns.Msg)
	msg.SetQuestion("test.com.", dns.TypeA)
	retARR, err := dns.NewRR(msg.Question[0].Name + " 60 IN A 1.1.1.1")
	if err != nil {
		panic(err)
	}
	msg.Answer = append(msg.Answer, retARR)

	// Case 1: NotifyOnDNSMsg is called successfully
	err = sdp.NotifyOnDNSMsg(time.Now(), ep, "1.1.1.1:80", serverId, "10.0.0.1", msg, "udp", true, nil)
	require.NoError(t, err)

	// Case 2: NotifyOnDNSMsg is called with invalid epIpPort
	err = sdp.NotifyOnDNSMsg(time.Now(), ep, "1.1.1.1", serverId, "10.0.0.1", msg, "udp", true, nil)
	require.Error(t, err)

	// Case 3: NotifyOnDNSMsg is called with nil client
	sdp.Client = nil
	err = sdp.NotifyOnDNSMsg(time.Now(), ep, "1.1.1.1:80", serverId, "10.0.0.1", msg, "udp", true, nil)
	require.Error(t, err)

	// Case 4: NotifyOnDNSMsg is called with invalid msg
	err = sdp.CreateClient(ctx)
	require.NoError(t, err)
	msg = new(dns.Msg)
	err = sdp.NotifyOnDNSMsg(time.Now(), ep, "1.1.1.1:80", serverId, "10.0.0.1", msg, "udp", true, nil)
	require.Equal(t, errors.New("Invalid DNS message"), err)

}

func TestCreateSubscriptionStream(t *testing.T) {
	ctx := context.Background()
	sdp, closer := setupStandaloneDNSProxy(t, ctx)
	defer closer()

	// First check if the subscription stream is created successfully
	err := sdp.CreateClient(ctx)
	require.NoError(t, err)

	err = sdp.createSubscriptionStream(ctx)
	require.NoError(t, err)
	require.NotNil(t, sdp.dnsRulesStream)

	// Now check if the subscription stream is created again if the dnsRulesStream is not nil
	current := sdp.dnsRulesStream
	err = sdp.createSubscriptionStream(ctx)
	require.NoError(t, err)
	require.NotNil(t, sdp.dnsRulesStream)
	require.NotEqual(t, current, sdp.dnsRulesStream)

	// Now check if the subscription stream is not created if the client is nil
	sdp.Client = nil
	err = sdp.createSubscriptionStream(ctx)
	require.Error(t, err)
}

func setupMapForTest(t *testing.T) *bpf.Map {
	testutils.PrivilegedTest(t)

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
	key := ipcache.NewKey(net.ParseIP("1.1.1.10"), mask, 0)
	err = testMap.Update(&key, &ipcache.RemoteEndpointInfo{
		SecurityIdentity: uint32(1),
	})
	require.NoError(t, err)
	var s map[string][]string = make(map[string][]string)
	testMap.Dump(s)
	fmt.Printf("map: %v\n", s)
	t.Cleanup(func() {
		require.NoError(t, testMap.Close())
	})

	return testMap
}

func TestLookupSecIDByIP(t *testing.T) {
	ctx := context.Background()
	sdp, closer := setupStandaloneDNSProxy(t, ctx)
	defer closer()

	setupMapForTest(t)

	// Case 1: LookupSecIDByIP is called successfully
	secID, found := sdp.LookupSecIDByIP(netip.MustParseAddr("1.1.1.10"))
	require.True(t, found)
	require.Equal(t, ipcachePkg.Identity{
		ID:     identity.NumericIdentity(1),
		Source: source.Local,
	}, secID)

	// Case 2: LookupSecIDByIP is called with invalid ip
	secID, found = sdp.LookupSecIDByIP(netip.MustParseAddr("2.2.2.2"))
	require.False(t, found)
	require.Equal(t, ipcachePkg.Identity{}, secID)
}

func TestLookEPByIP(t *testing.T) {
	ctx := context.Background()
	sdp, closer := setupStandaloneDNSProxy(t, ctx)
	defer closer()

	setupMapForTest(t)

	// Case 1: LookupEPByIP is called successfully
	ep, _, err := sdp.LookupEPByIP(netip.MustParseAddr("1.1.1.10"))
	require.NoError(t, err)
	require.NotNil(t, ep)
	require.Equal(t, identity.NumericIdentity(1), ep.SecurityIdentity.ID)

	// Case 2: LookupEPByIP is called with invalid ip
	ep, _, err = sdp.LookupEPByIP(netip.MustParseAddr("2.2.2.2"))
	require.Error(t, err)
	require.Nil(t, ep)
}
