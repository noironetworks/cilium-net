// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmdref

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

func NewCmd(parentCmd *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:    "cmdref [output directory]",
		Short:  "Generate command reference for clustermesh-apiserver to given output directory",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			genMarkdown(parentCmd, args[0])
		},
	}
}

func genMarkdown(cmd *cobra.Command, cmdRefDir string) {
	// Remove the line 'Auto generated by spf13/cobra on ...'
	cmd.DisableAutoGenTag = true
	if err := doc.GenMarkdownTreeCustom(cmd, cmdRefDir, filePrepend, linkHandler); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func linkHandler(s string) string {
	return s
}

func filePrepend(s string) string {
	// Prepend a HTML comment that this file is autogenerated. So that
	// users are warned before fixing issues in the Markdown files.  Should
	// never show up on the web.
	return fmt.Sprintf("%s\n\n", "<!-- This file was autogenerated via clustermesh-apiserver cmdref, do not edit manually-->")
}