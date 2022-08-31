/*
Copyright © 2022 Rémi Calizzano <remi.calizzano@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"github.com/spf13/cobra"
)

var refreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "",
	Long:  ``,
}

type refreshFlags struct {
	applicationName string
	upgrade         bool
	originBranch    string
	path            string
	fleetBranch     string
	values          []string
	sshHostname     string
	caFile          string
	privateKeyFile  string

	authorName  string
	authorEmail string
}

var refreshArgs refreshFlags

func init() {
	refreshCmd.PersistentFlags().StringVar(&refreshArgs.applicationName, "name", "", "name of the application to refresh (default to the name of the application)")
	refreshCmd.PersistentFlags().BoolVar(&refreshArgs.upgrade, "upgrade", false, "if true, the application will be upgraded with the latest changes from the `origin-branch` Git branch")
	refreshCmd.PersistentFlags().StringVar(&refreshArgs.originBranch, "origin-branch", "main", "Git branch of the application origin repository")
	refreshCmd.PersistentFlags().StringVar(&refreshArgs.path, "path", "", "path to kustomization in the application repository")
	refreshCmd.PersistentFlags().StringVar(&refreshArgs.fleetBranch, "fleet-branch", "main", "Git branch of the fleet repository")
	refreshCmd.PersistentFlags().
		StringArrayVar(&refreshArgs.values, "set-value", []string{}, "set values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)")
	refreshCmd.PersistentFlags().StringVar(&refreshArgs.sshHostname, "ssh-hostname", "", "SSH hostname, to be used when the SSH host differs from the HTTPS one")
	refreshCmd.PersistentFlags().StringVar(&refreshArgs.caFile, "ca-file", "", "path to TLS CA file used for validating self-signed certificates")
	refreshCmd.PersistentFlags().StringVar(&refreshArgs.privateKeyFile, "private-key-file", "", "path to a private key file used for authenticating to the Git SSH server")

	refreshCmd.PersistentFlags().StringVar(&refreshArgs.authorName, "author-name", "Lizz", "author name for Git commits")
	refreshCmd.PersistentFlags().StringVar(&refreshArgs.authorEmail, "author-email", "", "author email for Git commits")

	rootCmd.AddCommand(refreshCmd)
}
