// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/cilium/hive"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
)

func scriptCommands(cfg Config, w *Writer, m LBMaps, r reconciler.Reconciler[*Frontend]) hive.ScriptCmdsOut {
	if !cfg.EnableExperimentalLB {
		return hive.ScriptCmdsOut{}
	}

	var snapshot mapSnapshots
	return hive.NewScriptCmds(map[string]script.Cmd{
		"lb/prune": script.Command(
			script.CmdUsage{Summary: "Trigger pruning of load-balancing BPF maps"},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				r.Prune()
				return nil, nil
			},
		),
		"lb/maps-dump":     lbmapDumpCommand(m),
		"lb/maps-snapshot": lbmapSnapshotCommand(m, &snapshot),
		"lb/maps-restore":  lbmapRestoreCommand(m, &snapshot),

		"lb/service":  serviceCommand(w),
		"lb/frontend": frontendCommand(w),
		"lb/backend":  backendCommand(w),
	})
}

func serviceCommand(w *Writer) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Upsert or delete a service",
			Args:    "[-delete] [flags] service-name",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			reorderArgs(args)
			flags := flag.NewFlagSet("lb/service", flag.ContinueOnError)
			flags.SetOutput(s.LogWriter())
			delete := flags.Bool("delete", false, "Delete the service and all associated frontends")
			extTrafficPolicy := enumFlag(flags, "ext-traffic-policy", loadbalancer.SVCTrafficPolicyCluster, loadbalancer.SVCTrafficPolicies, "external traffic policy")
			intTrafficPolicy := enumFlag(flags, "int-traffic-policy", loadbalancer.SVCTrafficPolicyCluster, loadbalancer.SVCTrafficPolicies, "internal traffic policy")
			natPolicy := enumFlag(flags, "nat-policy", loadbalancer.SVCNatPolicyNone, loadbalancer.SVCNatPolicies, "protocol NAT policy")
			healthCheckNodePort := flags.Int("health-check-nodeport", 0, "NodePort health checker port number, 0 is disabled")
			if err := flags.Parse(args); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return nil, nil
				}
				return nil, script.ErrUsage
			}
			args = flags.Args()
			if len(args) < 1 {
				return nil, script.ErrUsage
			}

			var serviceName loadbalancer.ServiceName
			if namespace, name, found := strings.Cut(args[0], "/"); found {
				serviceName.Namespace = namespace
				serviceName.Name = name
			} else {
				return nil, fmt.Errorf("%q is an invalid service name", args[0])
			}

			txn := w.WriteTxn()
			var err error
			if *delete {
				err = w.DeleteServiceAndFrontends(txn, serviceName)
				if err == nil {
					s.Logf("Deleted service %q\n", serviceName)
				}
			} else {
				var old *Service
				old, err = w.UpsertService(txn, &Service{
					Name:                   serviceName,
					Source:                 source.LocalAPI,
					Labels:                 nil,
					Annotations:            nil,
					NatPolicy:              *natPolicy,
					ExtTrafficPolicy:       *extTrafficPolicy,
					IntTrafficPolicy:       *intTrafficPolicy,
					SessionAffinity:        false,
					SessionAffinityTimeout: 0,
					ProxyRedirect:          nil,
					HealthCheckNodePort:    uint16(*healthCheckNodePort),
					LoopbackHostPort:       false,
					SourceRanges:           nil,
				})
				if err == nil {
					if old == nil {
						s.Logf("Added service %q\n", serviceName)
					} else {
						s.Logf("Updated service %q\n", serviceName)
					}
				}
			}
			txn.Commit()
			return nil, err
		},
	)
}

func frontendCommand(w *Writer) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Upsert or delete frontends",
			Args:    "[flags] service-name frontend-address...",
			Detail: []string{
				"See 'lb/frontend -h' for supported flags.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			reorderArgs(args)
			flags := flag.NewFlagSet("lb/frontend", flag.ContinueOnError)
			flags.SetOutput(s.LogWriter())
			serviceType := enumFlag(flags, "type", loadbalancer.SVCTypeClusterIP, loadbalancer.SVCTypes, "Service type")
			portName := flags.String("portname", "", "Port name")
			delete := flags.Bool("delete", false, "Delete the service and associated frontends")
			if err := flags.Parse(args); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return nil, nil
				}
				return nil, script.ErrUsage
			}
			args = flags.Args()
			if len(args) < 2 {
				return nil, script.ErrUsage
			}

			var serviceName loadbalancer.ServiceName
			if namespace, name, found := strings.Cut(args[0], "/"); found {
				serviceName.Namespace = namespace
				serviceName.Name = name
			} else {
				return nil, fmt.Errorf("%q is an invalid service name", args[0])
			}

			var addrs []loadbalancer.L3n4Addr
			for _, arg := range args[1:] {
				frontend, err := loadbalancer.NewL3n4AddrFromString(arg)
				if err != nil {
					return nil, fmt.Errorf("%q is an invalid frontend address: %w", arg, err)
				}
				addrs = append(addrs, *frontend)
			}

			txn := w.WriteTxn()
			defer txn.Abort()

			var err error
			if *delete {
				for _, addr := range addrs {
					_, err = w.DeleteFrontend(txn, addr)
					if err != nil {
						return nil, err
					} else {
						s.Logf("Deleted frontend %q\n", addr.StringWithProtocol)
					}
				}
			} else {
				for _, addr := range addrs {
					var old *Frontend
					old, err = w.UpsertFrontend(txn, FrontendParams{
						Address:     addr,
						Type:        *serviceType,
						ServiceName: serviceName,
						PortName:    loadbalancer.FEPortName(*portName),
						ServicePort: addr.Port,
					})
					if err != nil {
						return nil, err
					} else {
						if old == nil {
							s.Logf("Added frontend %q\n", addr.StringWithProtocol())
						} else {
							s.Logf("Updated frontend %q\n", addr.StringWithProtocol())
						}
					}
				}
			}
			txn.Commit()
			return nil, nil
		},
	)
}

// TODO: switch BackendState from uint8 into a string.
var backendStateModels = []string{
	models.BackendAddressStateActive,
	models.BackendAddressStateTerminating,
	models.BackendAddressStateQuarantined,
	models.BackendAddressStateMaintenance,
}

func backendCommand(w *Writer) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Upsert or delete backends",
			Args:    "[flags] service-name backend-address...",
			Detail: []string{
				"See 'lb/backend -h' for supported flags.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			reorderArgs(args)
			flags := flag.NewFlagSet("lb/backend", flag.ContinueOnError)
			flags.SetOutput(s.LogWriter())
			delete := flags.Bool("delete", false, "Delete the backend(s)")
			portName := flags.String("portname", "", "Port name")
			stateModel := enumFlag(flags, "state", models.BackendAddressStateActive, backendStateModels, "State")

			weight := flags.Int("weight", 100, "Maglev weight")
			if err := flags.Parse(args); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return nil, nil
				}
				return nil, script.ErrUsage
			}
			args = flags.Args()
			if len(args) < 2 {
				return nil, script.ErrUsage
			}

			state, err := loadbalancer.GetBackendState(*stateModel)
			if err != nil {
				return nil, fmt.Errorf("%q is invalid state: %w", *stateModel, err)
			}
			if *weight == 0 {
				state = loadbalancer.BackendStateMaintenance
			}

			var serviceName loadbalancer.ServiceName
			if namespace, name, found := strings.Cut(args[0], "/"); found {
				serviceName.Namespace = namespace
				serviceName.Name = name
			} else {
				return nil, fmt.Errorf("%q is an invalid service name", args[0])
			}

			var addrs []loadbalancer.L3n4Addr
			for _, arg := range args[1:] {
				frontend, err := loadbalancer.NewL3n4AddrFromString(arg)
				if err != nil {
					return nil, fmt.Errorf("%q is an invalid frontend address: %w", arg, err)
				}
				addrs = append(addrs, *frontend)
			}

			txn := w.WriteTxn()
			defer txn.Abort()

			if *delete {
				for _, addr := range addrs {
					err = w.ReleaseBackend(txn, serviceName, addr)
					if err != nil {
						return nil, err
					}
					s.Logf("Released backend %q for %q\n", addr.StringWithProtocol(), serviceName)
				}
			} else {
				var backends []BackendParams
				for _, addr := range addrs {
					be := BackendParams{
						L3n4Addr: addr,
						PortName: *portName,
						Weight:   uint16(*weight),
						NodeName: "", // TODO
						ZoneID:   0,  // TODO
						State:    state,
					}
					backends = append(backends, be)
				}
				err = w.UpsertBackends(
					txn, serviceName, source.LocalAPI,
					backends...)
				if err != nil {
					return nil, err
				}
				s.Logf("Upserted backends %v\n", addrs)
			}

			txn.Commit()
			return nil, nil
		},
	)
}

func lbmapDumpCommand(m LBMaps) script.Cmd {
	if f, ok := m.(*FaultyLBMaps); ok {
		m = f.impl
	}
	return script.Command(
		script.CmdUsage{
			Summary: "Dump the load-balancing BPF maps",
			Args:    "(output file)",
			Detail: []string{
				"This dumps the load-balancer BPF maps either to stdout or to a file.",
				"Each BPF map key-value is shown as one line, e.g. backend would be:",
				"BE: ID=1 ADDR=10.244.1.1:80 STATE=active",
				"",
				"Format is not guaranteed to be stable as this command is only",
				"for testing and debugging purposes.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(s *script.State) (stdout string, stderr string, err error) {
				out := DumpLBMaps(
					m,
					false,
					nil,
				)
				data := strings.Join(out, "\n") + "\n"
				if len(args) == 1 {
					err = os.WriteFile(s.Path(args[0]), []byte(data), 0644)
				} else {
					stdout = data
				}
				return
			}, nil
		},
	)
}

func lbmapSnapshotCommand(m LBMaps, snapshot *mapSnapshots) script.Cmd {
	if f, ok := m.(*FaultyLBMaps); ok {
		m = f.impl
	}
	return script.Command(
		script.CmdUsage{
			Summary: "Snapshot the load-balancing BPF maps",
			Args:    "",
			Detail: []string{
				"Dump the load-balancing BPF maps into an in-memory snapshot",
				"which can be restored with lbmaps/restore. This is meant only",
				"for testing.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return nil, snapshot.snapshot(m)
		},
	)
}

func lbmapRestoreCommand(m LBMaps, snapshot *mapSnapshots) script.Cmd {
	if f, ok := m.(*FaultyLBMaps); ok {
		m = f.impl
	}
	return script.Command(
		script.CmdUsage{
			Summary: "Restore the load-balancing BPF maps from snapshot",
			Args:    "",
			Detail: []string{
				"Restore the load-balancing BPF map contents from a snapshot",
				"created with lbmaps/snapshot.",
				"The BPF maps are not cleared before restoring, so any existing",
				"values will not be removed.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return nil, snapshot.restore(m)
		},
	)
}

type enumValue[S ~string] struct {
	p    *S
	alts []S
}

func newEnumValue[S ~string](val S, alts []S, p *S) *enumValue[S] {
	*p = val
	return &enumValue[S]{
		p:    p,
		alts: alts,
	}
}

func (ev *enumValue[S]) Set(val string) error {
	val = strings.ToLower(val)
	for _, alt := range ev.alts {
		if strings.ToLower(string(alt)) == val {
			*ev.p = alt
			return nil
		}
	}
	return fmt.Errorf("%q not found from alternatives %v", val, ev.alts)
}

func (ev *enumValue[S]) Get() any {
	if ev == nil || ev.p == nil {
		return nil
	}
	return string(*ev.p)
}

func (ev *enumValue[S]) String() string {
	if ev == nil || ev.p == nil {
		return ""
	}
	return string(*ev.p)
}

func enumFlag[S ~string](fs *flag.FlagSet, name string, value S, alts []S, usage string) *S {
	var p S
	fs.Var(newEnumValue(value, alts, &p), name, fmt.Sprintf("%s (one of %v)", usage, alts))
	return &p
}

// reorderArgs moves all flags to the front.
func reorderArgs(args []string) {
	slices.SortStableFunc(
		args,
		func(a, b string) int {
			switch {
			case strings.HasPrefix(a, "-") && !strings.HasPrefix(b, "-"):
				return -1
			case strings.HasPrefix(b, "-") && !strings.HasPrefix(a, "-"):
				return 1
			default:
				return 0
			}
		},
	)
}
