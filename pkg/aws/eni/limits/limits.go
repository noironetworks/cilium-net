// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2017 Lyft, Inc.

package limits

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2_types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/sirupsen/logrus"

	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "aws-eni-limits")

var limits struct {
	lock.RWMutex
	m map[string]ipamTypes.Limits
}

func init() {
	limits.m = make(map[string]ipamTypes.Limits)
}

// Get returns the instance limits of a particular instance type.
func Get(instanceType string, api ec2API) (limit ipamTypes.Limits, ok bool) {

	limits.RLock()
	limit, ok = limits.m[instanceType]
	limits.RUnlock()
	if ok {
		return limit, true
	}

	// If not found, try to update from EC2 API
	ctx := context.Background()
	if err := UpdateFromEC2API(ctx, api); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			"instance-type": instanceType,
		}).Warning("Failed to update instance limits from EC2 API")
		return ipamTypes.Limits{}, false
	}

	limits.RLock()
	limit, ok = limits.m[instanceType]
	limits.RUnlock()
	if !ok {
		log.WithFields(logrus.Fields{
			"instance-type": instanceType,
		}).Error("Failed to find the limit after updating from EC2 API")
	}

	return limit, ok
}

// UpdateFromUserDefinedMappings updates limits from the given map.
func UpdateFromUserDefinedMappings(m map[string]string) (err error) {

	limits.Lock()
	defer limits.Unlock()

	for instanceType, limitString := range m {
		limit, err := parseLimitString(limitString)
		if err != nil {
			return err
		}
		// Add or overwrite limits
		limits.m[instanceType] = limit
	}
	return nil
}

type ec2API interface {
	GetInstanceTypes(context.Context) ([]ec2_types.InstanceTypeInfo, error)
}

// UpdateFromEC2API updates limits from the EC2 API via calling
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstanceTypes.html.
func UpdateFromEC2API(ctx context.Context, api ec2API) error {
	instanceTypeInfos, err := api.GetInstanceTypes(ctx)
	if err != nil {
		return err
	}

	limits.Lock()
	defer limits.Unlock()

	for _, instanceTypeInfo := range instanceTypeInfos {
		instanceType := string(instanceTypeInfo.InstanceType)
		adapterLimit := aws.ToInt32(instanceTypeInfo.NetworkInfo.MaximumNetworkInterfaces)
		ipv4PerAdapter := aws.ToInt32(instanceTypeInfo.NetworkInfo.Ipv4AddressesPerInterface)
		ipv6PerAdapter := aws.ToInt32(instanceTypeInfo.NetworkInfo.Ipv6AddressesPerInterface)
		hypervisorType := instanceTypeInfo.Hypervisor

		limits.m[instanceType] = ipamTypes.Limits{
			Adapters:       int(adapterLimit),
			IPv4:           int(ipv4PerAdapter),
			IPv6:           int(ipv6PerAdapter),
			HypervisorType: string(hypervisorType),
		}
	}

	return nil
}

// parseLimitString returns the Limits struct parsed from config string.
func parseLimitString(limitString string) (limit ipamTypes.Limits, err error) {
	intSlice := make([]int, 3)
	stringSlice := strings.Split(strings.ReplaceAll(limitString, " ", ""), ",")
	if len(stringSlice) != 3 {
		return limit, fmt.Errorf("invalid limit value")
	}
	for i, s := range stringSlice {
		intLimit, err := strconv.Atoi(s)
		if err != nil {
			return limit, err
		}
		intSlice[i] = intLimit
	}
	return ipamTypes.Limits{Adapters: intSlice[0], IPv4: intSlice[1], IPv6: intSlice[2]}, nil
}
