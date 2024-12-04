// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"context"
	"maps"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/client"
)

func TestScript(t *testing.T) {
	log := hivetest.Logger(t)
	scripttest.Test(t,
		context.Background(),
		func(t testing.TB, args []string) *script.Engine {
			h := hive.New(
				client.FakeClientCell,
				TablesCell,
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.TODO()))
			})
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))
			return &script.Engine{
				Cmds: cmds,
			}
		}, []string{}, "testdata/*.txtar")
}
