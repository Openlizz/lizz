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
	"github.com/openlizz/lizz/internal/repo"
	"github.com/spf13/cobra"
)

var removeGitCmd = &cobra.Command{
	Use:   "git",
	Short: "Remove an application from any Git server",
	Long:  `The remove command is used to remove an application already added to the cluster. The remove command does not delete the application repository.`,
	RunE:  removeGitCmdRun,
}

type removeGitFlags struct {
	fleetUrl string
	username string
	password string
}

var removeGitArgs removeGitFlags

func init() {
	removeGitCmd.Flags().StringVar(&removeGitArgs.fleetUrl, "fleet-url", "", "Git repository URL of the fleet repository")
	removeGitCmd.Flags().StringVarP(&removeGitArgs.username, "username", "u", "git", "basic authentication username")
	removeGitCmd.Flags().StringVarP(&removeGitArgs.password, "password", "p", "", "basic authentication password")

	removeCmd.AddCommand(removeGitCmd)
}

func removeGitCmdRun(cmd *cobra.Command, args []string) error {
	logger.V(0).Infof("Remove application...")

	clusterRepo, err := repo.CloneClusterRepo(
		&repo.CloneOptions{
			URL:            removeGitArgs.fleetUrl,
			Branch:         removeArgs.fleetBranch,
			Username:       removeGitArgs.username,
			Password:       removeGitArgs.password,
			PrivateKeyFile: removeArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
		},
		status,
	)
	if err != nil {
		return err
	}
	err = clusterRepo.OpenClusterConfig(status)
	if err != nil {
		return err
	}
	err = clusterRepo.RemoveApplication(removeArgs.applicationName, status)
	if err != nil {
		return err
	}
	err = clusterRepo.CommitPush(
		removeArgs.authorName,
		removeArgs.authorEmail,
		"[remove application] Remove "+removeArgs.applicationName+" from the cluster",
		"",
		removeArgs.fleetBranch,
		rootArgs.timeout,
		status,
	)
	if err != nil {
		return err
	}
	return nil
}
