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

var secretManagementCmd = &cobra.Command{
	Use:   "secret-management",
	Short: "",
	Long:  ``,
}

type secretManagementFlags struct {
	output           string
	path             string
	decryptionSecret string
	fleetBranch      string
	privateKeyFile   string

	authorName  string
	authorEmail string
}

var secretManagementArgs secretManagementFlags

func init() {
	secretManagementCmd.PersistentFlags().StringVarP(&secretManagementArgs.output, "ouput", "o", "secret.yaml", "output where to save the secret to apply")
	secretManagementCmd.PersistentFlags().StringVar(&secretManagementArgs.path, "path", "cluster/applications.yaml", "path to the applications yaml file")
	secretManagementCmd.PersistentFlags().StringVar(&secretManagementArgs.decryptionSecret, "decryption-secret", "sops-age", "name of the secret containing the AGE secret key")
	secretManagementCmd.PersistentFlags().StringVar(&secretManagementArgs.fleetBranch, "fleet-branch", "main", "Git branch of the fleet repository")
	secretManagementCmd.PersistentFlags().StringVar(&secretManagementArgs.privateKeyFile, "private-key-file", "", "path to a private key file used for authenticating to the Git SSH server")

	secretManagementCmd.PersistentFlags().StringVar(&secretManagementArgs.authorName, "author-name", "Lizz", "author name for Git commits")
	secretManagementCmd.PersistentFlags().StringVar(&secretManagementArgs.authorEmail, "author-email", "", "author email for Git commits")

	rootCmd.AddCommand(secretManagementCmd)
}
