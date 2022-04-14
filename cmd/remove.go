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
	"gitlab.com/openlizz/lizz/internal/repo"
)

var removeCmd = &cobra.Command{
	Use:   "remove",
	Short: "",
	Long:  ``,
	RunE:  removeCmdRun,
}

type removeFlags struct {
	applicationName string
	fleetUrl        string
	fleetBranch     string
	username        string
	password        string
	privateKeyFile  string

	authorName  string
	authorEmail string
}

var removeArgs removeFlags

func init() {
	removeCmd.Flags().StringVar(&removeArgs.applicationName, "name", "", "Name of the application to remove")
	removeCmd.Flags().StringVar(&removeArgs.fleetUrl, "fleet-url", "", "Git repository URL of the fleet repository")
	removeCmd.Flags().StringVar(&removeArgs.fleetBranch, "fleet-branch", "main", "Git branch of the fleet repository")
	removeCmd.Flags().StringVarP(&removeArgs.username, "username", "u", "git", "basic authentication username")
	removeCmd.Flags().StringVarP(&removeArgs.password, "password", "p", "", "basic authentication password")
	removeCmd.Flags().StringVar(&removeArgs.privateKeyFile, "private-key-file", "", "path to a private key file used for authenticating to the Git SSH server")

	removeCmd.Flags().StringVar(&removeArgs.authorName, "author-name", "Lizz", "author name for Git commits")
	removeCmd.Flags().StringVar(&removeArgs.authorEmail, "author-email", "", "author email for Git commits")

	rootCmd.AddCommand(removeCmd)
}

func removeCmdRun(cmd *cobra.Command, args []string) error {
	clusterRepo, err := repo.CloneClusterRepo(
		removeArgs.fleetUrl,
		removeArgs.fleetBranch,
		removeArgs.username,
		removeArgs.password,
		removeArgs.privateKeyFile,
		rootArgs.timeout,
	)
	if err != nil {
		return err
	}
	err = clusterRepo.OpenClusterConfig()
	if err != nil {
		return err
	}
	err = clusterRepo.RemoveApplication(removeArgs.applicationName)
	if err != nil {
		return err
	}
	err = clusterRepo.CommitPush(
		removeArgs.authorName,
		removeArgs.authorEmail,
		"[remove application] Remove "+removeArgs.applicationName+" from the cluster",
		"",
		rootArgs.timeout,
	)
	if err != nil {
		return err
	}
	return nil
}
