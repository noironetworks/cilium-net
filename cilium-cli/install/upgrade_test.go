// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaxHistory(t *testing.T) {
	assert := assert.New(t)

	p := Parameters{
		HelmMaxHistory: 15,
	}

	installer, err := NewK8sInstaller(nil, p)
	assert.NoError(err)
	assert.Equal(15, installer.params.HelmMaxHistory)
}
