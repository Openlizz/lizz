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

var removeGitCmd = &cobra.Command{
	Use:   "git",
	Short: "",
	Long:  ``,
	RunE:  removeGitCmdRun,
}

type removeGitFlags struct {
	fleetUrl       string
	username       string
	password       string
	privateKeyFile string
}

var removeGitArgs removeGitFlags

func init() {
	removeGitCmd.Flags().StringVar(&removeGitArgs.fleetUrl, "fleet-url", "", "Git repository URL of the fleet repository")
	removeGitCmd.Flags().StringVarP(&removeGitArgs.username, "username", "u", "git", "basic authentication username")
	removeGitCmd.Flags().StringVarP(&removeGitArgs.password, "password", "p", "", "basic authentication password")
	removeGitCmd.Flags().StringVar(&removeGitArgs.privateKeyFile, "private-key-file", "", "path to a private key file used for authenticating to the Git SSH server")

	removeCmd.AddCommand(removeGitCmd)
}

func removeGitCmdRun(cmd *cobra.Command, args []string) error {
	logger.Actionf("Clone the fleet repository.")
	clusterRepo, err := repo.CloneClusterRepo(
		&repo.CloneOptions{
			URL:            removeGitArgs.fleetUrl,
			Branch:         removeArgs.fleetBranch,
			Username:       removeGitArgs.username,
			Password:       removeGitArgs.password,
			PrivateKeyFile: removeGitArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
		},
	)
	if err != nil {
		return err
	}
	logger.Successf("")
	logger.Actionf("Remove the application.")
	err = clusterRepo.OpenClusterConfig()
	if err != nil {
		return err
	}
	err = clusterRepo.RemoveApplication(removeArgs.applicationName)
	if err != nil {
		return err
	}
	logger.Successf("")
	logger.Actionf("Commit and push to the fleet repository.")
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
	logger.Successf("")
	return nil
}
