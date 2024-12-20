package maps

import (
	"net"
	"net/netip"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ipcache"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "standalonednsproxy/maps")

func GetIdentity(ipAddr netip.Addr) (ipcache.RemoteEndpointInfo, error) {
	ip := net.ParseIP(ipAddr.String())
	clusterId := uint16(0)       // for non cluster mesh TODO: get cluster ID from the endpoint
	mask := net.CIDRMask(32, 32) // for IPv4, 32 bits for the network

	if ip.To16() != nil {
		mask = net.CIDRMask(128, 128) // for IPv6, 128 bits for the network
	}

	ipcacheMap, err := ipcache.LoadMap()
	if err != nil {
		log.Errorf("Cannot load config ipcache bpf map: %v", err)
		return ipcache.RemoteEndpointInfo{}, err
	}

	identityInfo, err := ipcacheMap.Get(ipcache.NewKey(ip, mask, clusterId))
	if err != nil {
		log.Errorf("Cannot load value for %v from ipcache bpf map: %v", ipAddr, err)
		return ipcache.RemoteEndpointInfo{}, err
	}
	log.Debugf("Identity info from ipcache bpf map: %v", identityInfo)

	return identityInfo, nil
}
