package service

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net"
	"net/netip"
	"testing"

	standalonednsproxy "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/hive/cell"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type dummyEpSyncher struct{}

func (epSync *dummyEpSyncher) RunK8sCiliumEndpointSync(e *endpoint.Endpoint, h cell.Health) {
}

func (epSync *dummyEpSyncher) DeleteK8sCiliumEndpointSync(e *endpoint.Endpoint) {
}

type Dummy struct {
	repo policy.PolicyRepository
}

func (s *Dummy) GetPolicyRepository() policy.PolicyRepository {
	return s.repo
}

func (s *Dummy) GetProxyPort(string) (uint16, error) {
	return 0, nil
}

func (s *Dummy) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	return nil, nil
}

func (s *Dummy) GetCompilationLock() datapath.CompilationLock {
	return nil
}

func (s *Dummy) GetCIDRPrefixLengths() (s6, s4 []int) {
	return nil, nil
}

func (s *Dummy) SendNotification(msg monitorAPI.AgentNotifyMessage) error {
	return nil
}

func (s *Dummy) Loader() datapath.Loader {
	return nil
}

func (s *Dummy) Orchestrator() datapath.Orchestrator {
	return nil
}

func (s *Dummy) BandwidthManager() datapath.BandwidthManager {
	return nil
}

func (s *Dummy) IPTablesManager() datapath.IptablesManager {
	return nil
}

func (s *Dummy) GetDNSRules(epID uint16) restore.DNSRules {
	return nil
}

func (s *Dummy) RemoveRestoredDNSRules(epID uint16) {}

func (s *Dummy) AddIdentity(id *identity.Identity) {}

func (s *Dummy) RemoveIdentity(id *identity.Identity) {}

func (s *Dummy) RemoveOldAddNewIdentity(old, new *identity.Identity) {}

func server(ctx context.Context) (*FQDNDataServer, standalonednsproxy.FQDNDataClient, func()) {
	buffer := 1024
	lis := bufconn.Listen(buffer)

	baseServer := grpc.NewServer()
	endptMgr := endpointmanager.New(&dummyEpSyncher{}, nil, nil)
	repo := policy.NewPolicyRepository(nil, nil, nil, nil)
	do := &Dummy{
		repo: repo,
	}
	// Add a test endpoint
	ep := endpoint.NewTestEndpointWithState(do, do, testipcache.NewMockIPCache(), &endpoint.FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), 1, endpoint.StateReady)
	ep.IPv4 = netip.MustParseAddr("1.1.1.1")
	err := endptMgr.ExposeTestEndpoint(ep)
	require.NoError(nil, err)

	server := NewServer(endptMgr,
		func(lookupTime time.Time, ep *endpoint.Endpoint, qname string, responseIPs []netip.Addr, TTL int, stat *dnsproxy.ProxyRequestContext) error {
			// Mocking the response for the test
			if qname == "example.com" {
				return nil
			}
			return errors.New("Failed to update fqdn mapping")
		},
	)
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

	closer := func() {
		server.ctx.Done()

		err := lis.Close()
		if err != nil {
			log.Printf("error closing listener: %v", err)
		}
		baseServer.Stop()
	}

	client := standalonednsproxy.NewFQDNDataClient(conn)

	return server, client, closer
}

func TestFQDNMapping(t *testing.T) {
	ctx := context.Background()

	_, client, closer := server(ctx)
	defer closer()

	type expected struct {
		out *standalonednsproxy.UpdatesMappingsResult
		err error
	}

	responseIps := []net.IP{
		net.ParseIP("2.2.2.2"),
	}
	var ips [][]byte
	for _, i := range responseIps {
		ips = append(ips, []byte(i.String()))
	}

	tests := map[string]struct {
		in       *standalonednsproxy.FQDNMapping
		expected expected
	}{
		"Success on updating the fqdn ips": {
			in: &standalonednsproxy.FQDNMapping{
				FQDN:           "example.com",
				IPS:            ips,
				TTL:            60,
				SourceIdentity: 1,
				SourceIp:       []byte("1.1.1.1"),
				ResponseCode:   0,
			},
			expected: expected{
				out: &standalonednsproxy.UpdatesMappingsResult{
					Success: true,
				},
				err: nil,
			},
		},
		"Failure due to update of fqdn ips": {
			in: &standalonednsproxy.FQDNMapping{
				FQDN:           "failure.com",
				IPS:            ips,
				TTL:            60,
				SourceIdentity: 1,
				SourceIp:       []byte("1.1.1.1"),
				ResponseCode:   0,
			},
			expected: expected{
				out: &standalonednsproxy.UpdatesMappingsResult{
					Success: false,
				},
				err: errors.New("rpc error: code = Unknown desc = cannot update DNS cache: Failed to update fqdn mapping"),
			},
		},
		"Success on response code non zero": {
			in: &standalonednsproxy.FQDNMapping{
				FQDN:           "example.com",
				IPS:            ips,
				TTL:            60,
				SourceIdentity: 1,
				SourceIp:       []byte("1.1.1.1"),
				ResponseCode:   1,
			},
			expected: expected{
				out: &standalonednsproxy.UpdatesMappingsResult{
					Success: true,
				},
				err: nil,
			},
		},
		"Failure due to endpoint not found": {
			in: &standalonednsproxy.FQDNMapping{
				FQDN:           "example.com",
				IPS:            ips,
				TTL:            60,
				SourceIdentity: 1,
				SourceIp:       []byte("1.1.1.0"),
				ResponseCode:   0,
			},
			expected: expected{
				out: &standalonednsproxy.UpdatesMappingsResult{
					Success: false,
				},
				err: errors.New("rpc error: code = Unknown desc = endpoint not found for IP: 1.1.1.0"),
			},
		},
		"Success if length of response ips is 0": {
			in: &standalonednsproxy.FQDNMapping{
				FQDN:           "example.com",
				IPS:            [][]byte{},
				TTL:            60,
				SourceIdentity: 1,
				SourceIp:       []byte("1.1.1.1"),
				ResponseCode:   0,
			},
			expected: expected{
				out: &standalonednsproxy.UpdatesMappingsResult{
					Success: true,
				},
				err: nil,
			},
		},
	}

	for scenario, tt := range tests {
		t.Run(scenario, func(t *testing.T) {
			out, err := client.UpdatesMappings(ctx, tt.in)
			require.Equal(t, tt.expected.out.GetSuccess(), out.GetSuccess())
			if err != nil {
				require.Equal(t, tt.expected.err.Error(), err.Error())
			} else {
				require.Equal(t, tt.expected.err, err)
			}
		})
	}
}

type dummySelectorPolicy struct{}

func (sp *dummySelectorPolicy) DistillPolicy(owner policy.PolicyOwner, redirects map[string]uint16) *policy.EndpointPolicy {
	return nil
}

const (
	dnsServerIdentity = identity.NumericIdentity(2)
	endpointIdentity  = identity.NumericIdentity(1)
)

func (sp *dummySelectorPolicy) RedirectFilters() iter.Seq2[*policy.L4Filter, *policy.PerSelectorPolicy] {
	sc := policy.NewSelectorCache(
		identity.IdentityMap{
			dnsServerIdentity: labels.LabelArray{
				labels.Label{
					Key:   "app",
					Value: "test",
				},
			},
		},
	)
	sc.SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())
	dummySelectorCacheUser := &testpolicy.DummySelectorCacheUser{}
	endpointSelector := api.NewESFromLabels(labels.ParseSelectLabel("app=test"))
	cachedSelector, _ := sc.AddIdentitySelector(dummySelectorCacheUser, nil, endpointSelector)
	expectedPolicy := policy.NewL4PolicyMapWithValues(map[string]*policy.L4Filter{
		"53/UDP": {
			Port:     53,
			Protocol: api.ProtoUDP,
			U8Proto:  0x11,
			L7Parser: policy.ParserTypeDNS,
			Ingress:  false,
			PerSelectorPolicies: policy.L7DataMap{
				cachedSelector: &policy.PerSelectorPolicy{
					L7Rules: api.L7Rules{
						DNS: []api.PortRuleDNS{
							{
								MatchName:    "example.com",
								MatchPattern: "*.cilium.io",
							},
						},
					},
				},
			},
		},
		"ANY/ANY": {
			Port:     0,
			Protocol: api.ProtoAny,
			U8Proto:  0x00,
			L7Parser: policy.ParserTypeDNS,
			Ingress:  false,
		},
		"ANY/UDP": {
			Port:     0,
			Protocol: api.ProtoAny,
			U8Proto:  0x00,
			L7Parser: policy.ParserTypeDNS,
			Ingress:  false,
			PerSelectorPolicies: policy.L7DataMap{
				cachedSelector: &policy.PerSelectorPolicy{
					L7Rules: api.L7Rules{
						DNS: []api.PortRuleDNS{},
					},
				},
			},
		},
	})

	// return the expected policy
	return func(yield func(*policy.L4Filter, *policy.PerSelectorPolicy) bool) {
		expectedPolicy.ForEach(func(l4 *policy.L4Filter) bool {
			return yield(l4, nil)
		})
	}
}

func TestSuccessfullySubscribeToDNSRules(t *testing.T) {
	ctx := context.Background()
	server, client, closer := server(ctx)
	defer closer()

	type in struct {
		snaptshot   map[identity.NumericIdentity]policy.SelectorPolicy
		policyRules *standalonednsproxy.DNSPolicies
	}

	tests := map[string]struct {
		in in
	}{
		"Success on sending the rules to the client": {
			in: in{
				snaptshot: map[identity.NumericIdentity]policy.SelectorPolicy{
					endpointIdentity: &dummySelectorPolicy{},
				},
				policyRules: &standalonednsproxy.DNSPolicies{
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
				},
			},
		},
		"Success on sending empty rules to the client": {
			in: in{
				snaptshot:   map[identity.NumericIdentity]policy.SelectorPolicy{},
				policyRules: &standalonednsproxy.DNSPolicies{},
			},
		},
	}

	for scenario, test := range tests {
		t.Run(scenario, func(t *testing.T) {
			// set the server snapshot
			server.currentSnapshot = test.in.snaptshot

			// Client subscribes to the DNS rules
			outClient, err := client.SubscribeToDNSPolicies(ctx)
			require.NoError(t, err)

			// Server sends the DNS rules
			for {
				actualOut, err := outClient.Recv()
				require.NoError(t, err)
				require.Equal(t, len(test.in.policyRules.GetEgressL7DnsPolicy()), len(actualOut.GetEgressL7DnsPolicy()))

				for i, expectedPolicy := range test.in.policyRules.GetEgressL7DnsPolicy() {
					actualPolicy := actualOut.GetEgressL7DnsPolicy()[i]
					require.Equal(t, expectedPolicy.GetSourceIdentity(), actualPolicy.GetSourceIdentity())
					require.Equal(t, expectedPolicy.GetDnsPattern(), actualPolicy.GetDnsPattern())
					require.Equal(t, len(expectedPolicy.GetDnsServers()), len(actualPolicy.GetDnsServers()))
					for j, expectedServer := range expectedPolicy.GetDnsServers() {
						actualServer := actualPolicy.GetDnsServers()[j]
						require.Equal(t, expectedServer.GetDnsServerPort(), actualServer.GetDnsServerPort())
						require.Equal(t, expectedServer.GetDnsServerProto(), actualServer.GetDnsServerProto())
					}
				}

				err = outClient.Send(&standalonednsproxy.DNSPoliciesResult{
					Success:   true,
					RequestId: actualOut.RequestId,
				})
				require.NoError(t, err)

				_, val := server.dnsMappingResult.Load(actualOut.RequestId)
				require.Equal(t, val, true)

				// Client closes the connection
				err = outClient.CloseSend()
				require.NoError(t, err)

				// Wait for a second before checking if the server has received the close signal
				sleepTime := time.NewTimer(1 * time.Second)
				<-sleepTime.C
				// Server receives the close signal and deletes the mapping
				_, val = server.dnsMappingResult.Load(actualOut.RequestId)
				require.False(t, val)
				break
			}
		})
	}
}

func TestFailureToSubscribeDNSRules(t *testing.T) {
	ctx := context.Background()
	server, client, closer := server(ctx)
	defer closer()

	// Client subscribes to the DNS rules
	outClient, err := client.SubscribeToDNSPolicies(ctx)
	require.NoError(t, err)

	for {
		actualOut, err := outClient.Recv()
		if err != nil {
			// This is expected as the server has received the success as false
			// So the client should receive an error and reestablish the stream
			require.Equal(t, "rpc error: code = Canceled desc = context canceled", err.Error())
			break
		}
		require.NoError(t, err)

		err = outClient.Send(&standalonednsproxy.DNSPoliciesResult{
			Success:   false,
			RequestId: actualOut.RequestId,
		})
		require.NoError(t, err)

		mapValue, _ := server.dnsMappingResult.Load(actualOut.RequestId)
		require.False(t, mapValue)
	}
}

func TestRunServer(t *testing.T) {
	test := map[string]struct {
		port   int
		server *FQDNDataServer
		err    error
	}{
		"Success on running the server": {
			port:   1234,
			server: &FQDNDataServer{},
			err:    nil,
		},
		"Failure on running the server": {
			port:   -1,
			server: &FQDNDataServer{},
			err:    errors.New("listen tcp: address -1: invalid port"),
		},
	}

	for scenario, tt := range test {
		t.Run(scenario, func(t *testing.T) {

			go func() {
				err := RunServer(tt.port, tt.server)
				if err != nil {
					require.Equal(t, tt.err.Error(), err.Error())
					// If the error is not nil, then terminate the test
					return
				} else {
					require.Equal(t, tt.err, err)
				}
			}()

			// Give the server some time to start
			time.Sleep(1 * time.Second)

			// Try to connect to the server
			conn, err := grpc.Dial(fmt.Sprintf("localhost:%d", tt.port), grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer conn.Close()

		})
	}
}
