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

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "",
	Long:  ``,
}

type initFlags struct {
	originUrl          string
	originBranch       string
	destinationBranch  string
	destinationPrivate bool
	sshHostname        string
	caFile             string
	privateKeyFile     string

	authorName  string
	authorEmail string
}

var initArgs initFlags

func init() {
	initCmd.PersistentFlags().StringVar(&initArgs.originUrl, "origin-url", "", "Git repository URL")
	initCmd.PersistentFlags().StringVar(&initArgs.originBranch, "origin-branch", "main", "Git branch of the repository")
	initCmd.PersistentFlags().StringVar(&initArgs.destinationBranch, "destination-branch", "main", "Git branch of the destination repository")
	initCmd.PersistentFlags().BoolVar(&initArgs.destinationPrivate, "private", true, "if true, the repository is setup or configured as private")
	initCmd.PersistentFlags().StringVar(&initArgs.sshHostname, "ssh-hostname", "", "SSH hostname, to be used when the SSH host differs from the HTTPS one")
	initCmd.PersistentFlags().StringVar(&initArgs.caFile, "ca-file", "", "path to TLS CA file used for validating self-signed certificates")
	initCmd.PersistentFlags().StringVar(&initArgs.privateKeyFile, "private-key-file", "", "path to a private key file used for authenticating to the Git SSH server")

	initCmd.PersistentFlags().StringVar(&initArgs.authorName, "author-name", "Lizz", "author name for Git commits")
	initCmd.PersistentFlags().StringVar(&initArgs.authorEmail, "author-email", "", "author email for Git commits")

	rootCmd.AddCommand(initCmd)
}
