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

var removeCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove an application",
	Long:  `The remove command is used to remove an application added to the cluster.`,
}

type removeFlags struct {
	applicationName string
	fleetBranch     string
	privateKeyFile  string

	authorName  string
	authorEmail string
}

var removeArgs removeFlags

func init() {
	removeCmd.PersistentFlags().StringVar(&removeArgs.applicationName, "name", "", "name of the application to remove")
	removeCmd.PersistentFlags().StringVar(&removeArgs.fleetBranch, "fleet-branch", "main", "Git branch of the fleet repository")
	removeCmd.PersistentFlags().StringVar(&removeArgs.privateKeyFile, "private-key-file", "", "path to a private key file used for authenticating to the Git SSH server")

	removeCmd.PersistentFlags().StringVar(&removeArgs.authorName, "author-name", "Lizz", "author name for Git commits")
	removeCmd.PersistentFlags().StringVar(&removeArgs.authorEmail, "author-email", "", "author email for Git commits")

	rootCmd.AddCommand(removeCmd)
}
