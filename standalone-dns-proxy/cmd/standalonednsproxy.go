package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"

	standalonednsproxy "github.com/cilium/cilium/api/v1/standalone-dns-proxy"

	"github.com/cilium/cilium/standalone-dns-proxy/pkg/maps"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
	ciliumdns "github.com/cilium/dns"
)

var kacp = keepalive.ClientParameters{
	Time:                10 * time.Second, // send pings every 10 seconds if there is no activity
	Timeout:             5 * time.Second,  // wait 1 second for ping ack before considering the connection dead
	PermitWithoutStream: true,             // send pings even without active streams
}

type StandaloneDNSProxyArgs struct {
	dnsproxy.DNSProxyConfig

	toFqdnServerPort         uint16
	enableL7Proxy            bool
	enableStandaloneDNsProxy bool
}

type StandaloneDNSProxy struct {
	// DNSProxy is the standalone DNS proxy
	DNSProxy *dnsproxy.DNSProxy

	// Client is the client for the standalone DNS proxy to connect to the cilium agent
	Client standalonednsproxy.FQDNDataClient

	// connection stores the grpc connection to the cilium agent
	connection *grpc.ClientConn

	// ciliumAgentConnectionTrigger is the trigger to connect to the cilium agent
	ciliumAgentConnectionTrigger *trigger.Trigger

	// mu is the mutex to protect creation of multiple DNS rules stream in case of multiple triggers
	mu lock.Mutex

	// dnsRulesStream is the stream to subscribe to the DNS rules
	dnsRulesStream standalonednsproxy.FQDNData_SubscribeToDNSPoliciesClient

	// cancelSubscribeToDNSRules is the cancel function for the DNS rules subscription
	cancelSubscribeToDNSRules context.CancelFunc

	// args are the arguments for the standalone DNS proxy
	args *StandaloneDNSProxyArgs
}

// NewStandaloneDNSProxy creates a new standalone DNS proxy
func NewStandaloneDNSProxy(args *StandaloneDNSProxyArgs) (*StandaloneDNSProxy, error) {
	if args.toFqdnServerPort == 0 {
		log.Error("toFqdnServerPort is 0")
		return nil, errors.New("toFqdnServerPort is 0")
	}

	return &StandaloneDNSProxy{
		args: args,
	}, nil
}

func (sdp *StandaloneDNSProxy) StopStandaloneDNSProxy() error {
	if sdp.DNSProxy != nil {
		sdp.DNSProxy.Cleanup()
	}

	err := sdp.closeConnection()
	if err != nil {
		log.WithError(err).Error("Failed to close connection")
		return err
	}
	return nil
}

// CreateClient creates a client for the cilium agent connection
// 1. It checks if connection is created, if not it returns an error and triggers the cilium agent connection trigger
// 2. Else it creates the client
// 3. If the DNS rules stream is not created, it creates the stream
// Note: This function is called with a mutex lock in the caller function because there can be multiple triggers trying to
// create the stream at the same time
func (sdp *StandaloneDNSProxy) CreateClient(ctx context.Context) error {
	var err error
	defer func() {
		if err != nil {
			log.WithError(err).Error("Failed to start cilium agent connection")
			sdp.closeConnection()
			sdp.ciliumAgentConnectionTrigger.TriggerWithReason("Failed to start cilium agent connection")
		}
	}()

	if sdp.connection == nil {
		log.Error("Connection is nil")
		return fmt.Errorf("connection is nil")
	}

	// Create the client
	sdp.Client = standalonednsproxy.NewFQDNDataClient(sdp.connection)

	if sdp.dnsRulesStream == nil {
		err = sdp.createSubscriptionStream(ctx)
		if err != nil {
			log.WithError(err).Error("Failed to create subscription stream")
			return err
		}
	}
	log.Debugf("Successfully created client for Cilium agent")

	return nil
}

// ConnectToCiliumAgent creates a connection to the cilium agent
// It returns an error if the connection is not successful and triggers the cilium agent connection trigger
func (sdp *StandaloneDNSProxy) ConnectToCiliumAgent() error {
	var err error
	defer func() {
		if err != nil {
			log.Errorf("Failed to connect to cilium agent: %v", err)
			sdp.ciliumAgentConnectionTrigger.TriggerWithReason("Failed to connect to cilium agent")
		}
	}()

	if sdp.connection != nil {
		return nil
	}

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	opts = append(opts, grpc.WithBlock())
	opts = append(opts, grpc.WithKeepaliveParams(kacp))

	address := fmt.Sprintf("localhost:%d", sdp.args.toFqdnServerPort)

	log.Infof("Connecting to server %v", address)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5) // 5 seconds timeout
	defer cancel()

	conn, err := grpc.DialContext(ctx, address, opts...)
	if err != nil {
		log.Errorf("Failed to connect to server %v at address %s", err, address)
		return err
	}
	log.Infof("Connected to server %v", address)
	sdp.connection = conn

	return nil // Successfully connected
}

// StartStandaloneDNSProxy starts the standalone DNS proxy and creates the cilium agent connection trigger
// The flow is as follows:
// 1. It starts the DNS Proxy
// 2. It creates the cilium agent connection trigger
// 3. It triggers the cilium agent connection trigger
func (sdp *StandaloneDNSProxy) StartStandaloneDNSProxy() error {
	var err error

	if !sdp.args.enableL7Proxy {
		log.Info("L7 Proxy is disabled")
		return nil
	}

	if !sdp.args.enableStandaloneDNsProxy {
		log.Info("Standalone DNS Proxy is disabled")
		return nil
	}

	// Initialize the DNS Proxy
	sdp.DNSProxy, err = dnsproxy.StartDNSProxy(sdp.args.DNSProxyConfig, sdp.LookupEPByIP, sdp.LookupSecIDByIP, sdp.LookupIPsBySecID, sdp.NotifyOnDNSMsg)
	if err != nil {
		log.WithError(err).Fatal("Failed to start DNS Proxy")
		return err
	}
	log.Infof("DNS Proxy started on %s:%d", sdp.args.Address, sdp.args.Port)

	// Create the cilium agent connection trigger
	err = sdp.createciliumAgentConnectionTriggerTrigger()
	if err != nil {
		log.WithError(err).Error("Failed to create the trigger for connecting to Cilium agent")
		return err
	}

	// trigger the cilium agent connection
	sdp.ciliumAgentConnectionTrigger.TriggerWithReason("Start standalone DNS proxy")
	return nil
}

// createciliumAgentConnectionTriggerTrigger creates a trigger to connect to the cilium agent
// 1. It tries to connect to the cilium agent
// 2. If the connection is successful, it tries to start the grpc streams
// 3. If the streams are started, it tries to subscribe to the DNS rules as go routine
func (sdp *StandaloneDNSProxy) createciliumAgentConnectionTriggerTrigger() error {
	var err error
	sdp.ciliumAgentConnectionTrigger, err = trigger.NewTrigger(trigger.Parameters{
		Name:        "start-cilium-agent-connection",
		MinInterval: 5 * time.Second,
		TriggerFunc: func(reasons []string) {
			defer func() {
				if r := recover(); r != nil {
					log.Errorf("Recovered from panic in trigger function: %v", r)
				}
			}()
			log.Infof("Triggering cilium agent connection: %v", reasons)
			// 1. Try creating the connection to the cilium agent
			err := sdp.ConnectToCiliumAgent()
			if err != nil {
				log.WithError(err).Error("Failed to connect to cilium agent")
				return
			}

			sdp.mu.Lock()
			defer sdp.mu.Unlock()
			// 2. Try starting the cilium agent connection
			// only create the client if no stream is already open
			// Imagine a scenarios where two triggers are fired at the same time
			// and both try to create the client at the same time
			// Due to the mutex, only one of them will create the client and start the stream
			// The other one will just return
			if sdp.dnsRulesStream == nil {
				ctx, cancel := context.WithCancel(context.Background())

				err = sdp.CreateClient(ctx)
				if err != nil {
					log.WithError(err).Error("Failed to create client")
					cancel()
					return
				}

				// 3. Try to subscribe to the DNS rules
				sdp.cancelSubscribeToDNSRules = cancel // Store the cancel function for later use
				go sdp.subscribeToDNSRules(ctx)
			}
		},
	})
	if err != nil {
		log.Errorf("Failed to create trigger: %v", err)
		return err // Return the error after logging
	}
	return nil
}

// Note: isHost is always false as it is not used in the current implementation
// TODO: Remove isHost from the function signature
func (sdp *StandaloneDNSProxy) LookupEPByIP(ip netip.Addr) (ep *endpoint.Endpoint, isHost bool, err error) {
	log.Debugf("LookupEPByIP: %s", ip.String())

	secId, err := maps.GetIdentity(ip)
	if err != nil {
		log.WithError(err).Errorf("Failed to get identity for IP %s", ip.String())
		return nil, false, err
	}
	endpt := &endpoint.Endpoint{
		SecurityIdentity: &identity.Identity{
			ID: identity.NumericIdentity(secId.SecurityIdentity),
		},
	}
	log.Debugf("Endpoint Identity found: %v", endpt)

	return endpt, false, nil
}

func (sdp *StandaloneDNSProxy) LookupIPsBySecID(nid identity.NumericIdentity) []string {
	return nil
}

func (sdp *StandaloneDNSProxy) LookupSecIDByIP(ip netip.Addr) (secID ipcache.Identity, exists bool) {
	log.Debugf("LookupSecIDByIP: %s", ip.String())
	secId, err := maps.GetIdentity(ip)
	if err != nil {
		log.WithError(err).Errorf("Failed to get identity for IP %s", ip.String())
		return ipcache.Identity{}, false
	}

	log.Debugf("Identity found: %v", secId)
	return ipcache.Identity{
		ID:     identity.NumericIdentity(secId.SecurityIdentity),
		Source: source.Local, // Local source means the identity is from the local agent
	}, true
}

func (sdp *StandaloneDNSProxy) NotifyOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddr string, msg *ciliumdns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
	log.Debugf("Received DNS message: %v", msg)
	qname, responseIPs, TTL, _, rcode, _, _, err := dnsproxy.ExtractMsgDetails(msg)
	if err != nil {
		log.WithError(err).Error("cannot extract DNS message details")
		return err
	}

	var ips [][]byte
	for _, i := range responseIPs {
		log.Debugf("%s is mapped to %s", qname, i.String())
		ips = append(ips, []byte(i.String()))
	}

	sourceIp, _, err := net.SplitHostPort(epIPPort)
	if err != nil {
		log.WithError(err).Error("Failed to split IP:Port")
		return err
	}

	sourceIdentity, err := ep.GetSecurityIdentity()
	if err != nil {
		log.WithError(err).Error("Failed to get security identity")
	}
	message := &standalonednsproxy.FQDNMapping{
		FQDN:           qname,
		IPS:            ips,
		TTL:            TTL,
		SourceIp:       []byte(sourceIp),
		SourceIdentity: uint32(sourceIdentity.ID),
		ResponseCode:   uint32(rcode),
	}
	log.Debugf("Sending FQDN Mapping message: %v", message)
	if sdp.Client == nil {
		log.Error("Client is nil")
		return fmt.Errorf("client is nil")
	}
	result, err := sdp.Client.UpdatesMappings(context.Background(), message)
	log.Debugf("Received result from FQDN mapping stream %v", result)
	if err != nil {
		log.WithError(err).Error("Failed to send FQDN Mapping message")
		return err
	}

	return nil
}

// subscribeToDNSRules subscribes to the DNS rules
// 1. Tries to get the stream connected
// 2. If the stream is connected, it waits for the DNS rules to be received
func (sdp *StandaloneDNSProxy) subscribeToDNSRules(ctx context.Context) error {
	var err error
	defer func() {
		if err != nil {
			sdp.closeDNSRuleStream()
			reason := "Failed to subscribe to DNS rules"
			switch status.Code(err) {
			case codes.Unavailable:
				sdp.closeConnection()
				reason = "DNS server unavailable"
			default:
				if err == io.EOF {
					sdp.closeConnection()
					reason = "Received EOF from DNS rules stream"
					log.Error("Received EOF from DNS rules stream")
				} else {
					log.WithError(err).Error("Failed to subscribe to DNS rules")
				}
			}
			sdp.ciliumAgentConnectionTrigger.TriggerWithReason(reason)
		}
		sdp.cancelSubscribeToDNSRules()
	}()

	for {
		select {
		case <-ctx.Done():
			// Context was cancelled, exit goroutine
			log.Info("Stopping subscription to DNS rules")
			return nil
		default:
			log.Debugf("Waiting for DNS rules")
			newRules, recvErr := sdp.dnsRulesStream.Recv()
			if recvErr != nil {
				if recvErr == io.EOF || status.Code(recvErr) == codes.Unavailable {
					log.WithError(recvErr).Error("DNS rules stream closed")
					err = recvErr
					return err
				}
				log.WithError(recvErr).Error("Failed to receive DNS rules")
				err = recvErr // Set the outer err for the deferred function to handle.
				return err
			}
			log.WithField("newRules", newRules).Debug("Received DNS rule")

			response := &standalonednsproxy.DNSPoliciesResult{
				Success:   false,
				RequestId: newRules.GetRequestId(),
			}
			err = sdp.DNSProxy.UpdateAllowedIdentities(newRules)
			if err != nil {
				log.WithError(err).Error("Failed to update DNS rules")
				err = sdp.dnsRulesStream.Send(response)
				if err != nil {
					log.WithError(err).Error("Failed to send DNS policies result")
					return err
				}
				return err
			}
			response.Success = true
			err = sdp.dnsRulesStream.Send(response)
			if err != nil {
				log.WithError(err).Error("Failed to send DNS policies result")
				return err
			}
		}
	}
}

func (sdp *StandaloneDNSProxy) closeDNSRuleStream() {
	if sdp.dnsRulesStream != nil {
		err := sdp.dnsRulesStream.CloseSend()
		if err != nil {
			log.Errorf("Failed to close DNS rules stream: %v", err)
		}
		sdp.dnsRulesStream = nil
	}
}

func (sdp *StandaloneDNSProxy) closeConnection() error {
	if sdp.connection != nil {
		err := sdp.connection.Close()
		if err != nil {
			log.Errorf("Failed to close connection: %v", err)
			return err
		}
		sdp.connection = nil
	}
	return nil
}

// createSubscriptionStream creates a subscription stream to the DNS rules
func (sdp *StandaloneDNSProxy) createSubscriptionStream(ctx context.Context) error {
	if sdp.Client == nil {
		log.Error("Client is nil")
		return fmt.Errorf("client is nil")
	}

	if sdp.dnsRulesStream != nil {
		log.Error("DNS rules stream is not nil")
		sdp.closeDNSRuleStream()
	}

	stream, err := sdp.Client.SubscribeToDNSPolicies(ctx)
	if err != nil {
		log.WithError(err).Error("Failed to subscribe to DNS rules")
		return err
	}
	sdp.dnsRulesStream = stream
	return nil
}
