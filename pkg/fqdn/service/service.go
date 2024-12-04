package service

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	standalonednsproxy "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/dns"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

type updateOnDNSMsgFunc func(lookupTime time.Time, ep *endpoint.Endpoint, qname string, responseIPs []netip.Addr, TTL int, stat *dnsproxy.ProxyRequestContext) error

type FQDNDataServer struct {
	standalonednsproxy.UnimplementedFQDNDataServer

	ctx             context.Context
	closeServer     func()
	endpointManager endpointmanager.EndpointManager

	// streams is a map of the active streams and their cancel functions
	// Streams are added when a client(standalone dns proxy) subscribes to DNS policies and removed when the client closes the connection
	streams lock.Map[standalonednsproxy.FQDNData_SubscribeToDNSPoliciesServer, context.CancelFunc]

	// updateOnDNSMsg is a function to update the DNS message in the cilium agent on receiving the FQDN mapping
	updateOnDNSMsg updateOnDNSMsgFunc

	// dnsMappingResult is a map of the dns request id and bool value for success/failure
	dnsMappingResult lock.Map[string, bool]

	// snapshotMutex is a mutex to protect the current state of the DNS rules
	snapshotMutex lock.Mutex

	// currentSnapshot is the current state of the DNS rules
	currentSnapshot map[identity.NumericIdentity]policy.SelectorPolicy
}

var (
	log  = logging.DefaultLogger.WithField(logfields.LogSubsys, "fqdn/server")
	kaep = keepalive.EnforcementPolicy{
		PermitWithoutStream: true, // Allow pings even when there are no active streams
	}
	kasp = keepalive.ServerParameters{
		Time:    5 * time.Second, // Ping the client if it is idle for 5 seconds to ensure the connection is still active
		Timeout: 1 * time.Second, // Wait 1 second for the ping ack before assuming the connection is dead
	}
)

// SubscribeToDNSPolicies is a bidirectional streaming RPC to subscribe to DNS policies
// SDP calls this method to subscribe to DNS policies
// For each stream, we start a goroutine to receive the DNS policies ACKs
// The flow of the method is as follows:
// 1. Add the stream to the map( called by the client i.e SDP)
// 2. Start a goroutine to receive the DNS policies ACKs for that particular client.
// 3. Send the current state of the DNS rules to the client (We store the current state fo DNS rules during the endpoint regeneration see UpdatePolicyRulesLocked)
// 4. Wait for the context to be done
func (s *FQDNDataServer) SubscribeToDNSPolicies(stream standalonednsproxy.FQDNData_SubscribeToDNSPoliciesServer) error {
	streamCtx, cancel := context.WithCancel(stream.Context())
	s.streams.Store(stream, cancel)

	go func() {
		<-streamCtx.Done()
		// If the client has closed the connection, the context will be done
		log.Info("Client has closed the connection, closing the stream")
		s.DeleteStream(stream)
	}()

	// Start a goroutine to receive the DNS policies ACKs
	go func() {
		if err := s.ReceiveDNSpolicesACK(stream); err != nil {
			log.Errorf("Error receiving DNS policies ACK: %v", err)
			cancel() // Cancel the context to close the stream
		}
	}()

	//Send the current state of the DNS rules
	go func() {
		log.Debugf("Sending current state of DNS rules")

		// Send the current state of the DNS rules
		s.snapshotMutex.Lock()
		currentSnapshot := s.currentSnapshot
		s.snapshotMutex.Unlock()
		if err := s.UpdatePolicyRulesLocked(currentSnapshot); err != nil {
			log.Errorf("Error sending current state of DNS rules: %v", err)
			cancel() // Cancel the context to close the stream
		}
	}()

	log.Debugf("SubscribeToDNSPolicies waiting for context to be done")
	select {
	case <-streamCtx.Done():
		log.Info("Closing the stream")
		s.DeleteStream(stream)
		return streamCtx.Err()
	case <-s.ctx.Done():
		s.closeServer()
		log.Info("SubscribeToDNSPolicies done")
		return s.ctx.Err()
	}
}

// ReceiveDNSpolicesACK receives the DNS policies ACKs from the client
// If the success is false, we can send cancel signal to the channel
// in that case SDP will recreate the stream.
func (s *FQDNDataServer) ReceiveDNSpolicesACK(stream standalonednsproxy.FQDNData_SubscribeToDNSPoliciesServer) error {
	for {
		select {
		case <-s.ctx.Done():
			s.closeServer()
			log.Info("Stopping the stream")
			return s.ctx.Err()
		case <-stream.Context().Done():
			log.Info("Stream context is finished, closing the stream")
			return stream.Context().Err()
		default:
			update, err := stream.Recv()
			if err != nil {
				log.Errorf("Failed to receive update: %v", err)
				return err
			}
			log.Debugf("Received update: %v", update)
			requestId := update.GetRequestId()
			_, ok := s.dnsMappingResult.Load(requestId)
			if !ok {
				log.Errorf("Received Message id not found %s", requestId)
			} else {
				log.Debugf("Received response for dns message id: %s", requestId)

				// We can send cancel signal to the channel if the success is false,
				// in that case SDP will recreate the stream.
				if !update.GetSuccess() {
					// If the success is false, we can send cancel signal to the channel
					// in that case SDP will recreate the stream.
					log.Errorf("Failed to update DNS policies")
					cancel, ok := s.streams.Load(stream)
					if ok {
						cancel()
					}
				}
			}
			// Delete the response channel from the map
			s.dnsMappingResult.Delete(requestId)
			log.Debugf("Deleted from local cache for dns message id: %s", requestId)
		}
	}
}

// NewServer creates a new FQDNDataServer which is used to handle the Standalone DNS Proxy grpc service
func NewServer(endpointManager endpointmanager.EndpointManager, updateOnDNSMsg updateOnDNSMsgFunc) *FQDNDataServer {
	ctx := context.Background()

	s := &FQDNDataServer{
		endpointManager: endpointManager,
		updateOnDNSMsg:  updateOnDNSMsg,
		ctx:             ctx,
		streams:         lock.Map[standalonednsproxy.FQDNData_SubscribeToDNSPoliciesServer, context.CancelFunc]{},
		currentSnapshot: make(map[identity.NumericIdentity]policy.SelectorPolicy),
	}

	go func() {
		<-s.ctx.Done()
		log.Info("FQDN service context done, cleaning up resources")
		s.cleanupStreams()
		s.closeServer()
	}()

	return s
}

// UpdatePolicyRulesLocked updates the current state of the DNS rules
// This method is called when the DNS rules are updated during the endpoint regeneration
// It also stores the current state of the DNS rules for new clients connecting to the server
// We send the DNS rules to the client(standalone dns proxy) using the stream
func (s *FQDNDataServer) UpdatePolicyRulesLocked(policies map[identity.NumericIdentity]policy.SelectorPolicy) error {
	s.snapshotMutex.Lock()
	defer s.snapshotMutex.Unlock()

	s.currentSnapshot = policies

	egressL7DnsPolicy := make([]*standalonednsproxy.DNSPolicy, 0, len(policies))
	for identity, pol := range policies {
		for l4 := range pol.RedirectFilters() {
			parseType := l4.GetL7Parser()
			if parseType == policy.ParserTypeDNS {
				if l4.PerSelectorPolicies == nil {
					continue
				}
				for cs, sp := range l4.PerSelectorPolicies {
					if len(sp.DNS) == 0 {
						continue
					}
					dnsServers := make([]*standalonednsproxy.DNSServer, 0, len(cs.GetSelections(versioned.Latest())))
					for _, sel := range cs.GetSelections(versioned.Latest()) {
						dnsServers = append(dnsServers, &standalonednsproxy.DNSServer{
							DnsServerIdentity: uint32(sel),
							DnsServerPort:     uint32(l4.GetPort()),
							DnsServerProto:    uint32(l4.U8Proto),
						})
					}
					dnsPattern := make([]string, 0, len(sp.DNS))
					for _, dns := range sp.DNS {
						if dns.MatchPattern != "" {
							dnsPattern = append(dnsPattern, dns.MatchPattern)
						}
						if dns.MatchName != "" {
							dnsPattern = append(dnsPattern, dns.MatchName)
						}
					}
					egressL7DnsPolicy = append(egressL7DnsPolicy, &standalonednsproxy.DNSPolicy{
						SourceIdentity: uint32(identity),
						DnsServers:     dnsServers,
						DnsPattern:     dnsPattern,
					})
				}
			}
		}
	}

	requestId := uuid.New().String()
	dnsPolices := &standalonednsproxy.DNSPolicies{
		RequestId: requestId,
	}

	log.Debugf("Current EgressL7DnsPolicy: %v for request Id %v", egressL7DnsPolicy, requestId)
	dnsPolices.EgressL7DnsPolicy = egressL7DnsPolicy

	log.Debugf("Sending Policy updates to sdp: %v", dnsPolices)
	s.streams.Range(func(stream standalonednsproxy.FQDNData_SubscribeToDNSPoliciesServer, cancel context.CancelFunc) bool {
		log.Debugf("Sending update to stream: %v", stream)
		s.dnsMappingResult.Store(requestId, false)
		if err := stream.Send(dnsPolices); err != nil {
			log.Errorf("Failed to send update: %v", err)
			// Cancel the goroutine and remove the stream from the map
			cancel()
		}
		return true
	})
	return nil
}

// DeleteStream deletes the stream from the map
func (s *FQDNDataServer) DeleteStream(stream standalonednsproxy.FQDNData_SubscribeToDNSPoliciesServer) {
	_, ok := s.streams.Load(stream)
	if ok {
		log.Infof("Deleting stream: %v", stream)
		s.streams.Delete(stream)
	} else {
		log.Warnf("Stream not found: %v", stream)
	}

}

// cleanupStreams handles the cleanup of streams when the server's context is cancelled.
func (s *FQDNDataServer) cleanupStreams() {
	s.streams.Range(func(key standalonednsproxy.FQDNData_SubscribeToDNSPoliciesServer, cancelFunc context.CancelFunc) bool {
		cancelFunc() // Ensure we cancel the context of each stream
		s.streams.Delete(key)
		return true
	})
	log.Info("All streams have been cleaned up")
}

// UpdatesMappings updates the FQDN mapping with the given data
// SDP sends the fqdn mapping to cilium agent
// Steps to update the mapping:
// 1. Get the endpoint from the IP
// 2. If the endpoint is not found, return an error
// 3. If the IPs are not empty, update the cilium agent with the mapping
func (s *FQDNDataServer) UpdatesMappings(ctx context.Context, mappings *standalonednsproxy.FQDNMapping) (*standalonednsproxy.UpdatesMappingsResult, error) {
	log.Debugf("UpdateMappings %v", mappings)
	now := time.Now()
	var ips []netip.Addr

	endpointAddr := netip.MustParseAddr(string(mappings.SourceIp))

	ep := s.endpointManager.LookupIP(endpointAddr)
	if ep == nil {
		log.Errorf("endpoint not found for IP: %s", mappings.SourceIp)
		// return fmt.Errorf("endpoint not found for IP: %s", mappings.ClientIp)
		return &standalonednsproxy.UpdatesMappingsResult{}, fmt.Errorf("endpoint not found for IP: %s", mappings.SourceIp)
	}

	if len(mappings.GetIPS()) == 0 {
		// We don't have any IPs to update the mappings with
		return &standalonednsproxy.UpdatesMappingsResult{
			Success: true,
		}, nil
	}

	for _, ip := range mappings.GetIPS() {
		ips = append(ips, netip.MustParseAddr(string(ip)))
	}

	if mappings.GetResponseCode() == dns.RcodeSuccess {
		err := s.updateOnDNSMsg(now, ep, mappings.GetFQDN(), ips, int(mappings.GetTTL()), nil)
		if err != nil {
			return &standalonednsproxy.UpdatesMappingsResult{}, fmt.Errorf("cannot update DNS cache: %v", err)
		}
	}

	return &standalonednsproxy.UpdatesMappingsResult{
		Success: true,
	}, nil
}

// RunServer starts the Standalone DNS Proxy grpc server on the given port
func RunServer(port int, server *FQDNDataServer) error {
	address := fmt.Sprintf("localhost:%d", port)
	log.Infof("Starting Standalone DNS Proxy grpc service on %s", address)
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Errorf("failed to listen: %v", err)
		return err
	}
	grpcServer := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	standalonednsproxy.RegisterFQDNDataServer(grpcServer, server)

	if err := grpcServer.Serve(lis); err != nil {
		log.Errorf("failed to serve: %v", err)
		return err
	}

	closer := func() {
		grpcServer.GracefulStop()
	}
	server.closeServer = closer
	return nil
}
