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

	"github.com/openlizz/lizz/internal/repo"
)

var secretManagementGitCmd = &cobra.Command{
	Use:   "git",
	Short: "Configure secret management for any Git server",
	Long:  `The secret-management command is used to configure Kubernetes secrets management with Mozilla SOPS. It generates a age key, store the public key in the fleet repository, and store the private key in a yaml file to apply it.`,
	RunE:  secretManagementGitCmdRun,
}

type secretManagementGitFlags struct {
	fleetUrl string
	username string
	password string
}

var secretManagementGitArgs secretManagementGitFlags

func init() {
	secretManagementGitCmd.Flags().StringVar(&secretManagementGitArgs.fleetUrl, "fleet-url", "", "Git repository URL of the fleet repository")
	secretManagementGitCmd.Flags().StringVarP(&secretManagementGitArgs.username, "username", "u", "git", "basic authentication username")
	secretManagementGitCmd.Flags().StringVarP(&secretManagementGitArgs.password, "password", "p", "", "basic authentication password")

	secretManagementCmd.AddCommand(secretManagementGitCmd)
}

func secretManagementGitCmdRun(cmd *cobra.Command, args []string) error {
	logger.V(0).Infof("Configure secret management...")

	clusterRepo, err := repo.CloneClusterRepo(
		&repo.CloneOptions{
			URL:            secretManagementGitArgs.fleetUrl,
			Branch:         secretManagementArgs.fleetBranch,
			Username:       secretManagementGitArgs.username,
			Password:       secretManagementGitArgs.password,
			PrivateKeyFile: secretManagementArgs.privateKeyFile,
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
	err = clusterRepo.ConfigureSecretManagement(
		secretManagementArgs.decryptionSecret,
		secretManagementArgs.output,
		secretManagementArgs.path,
		status,
	)
	if err != nil {
		return err
	}
	err = clusterRepo.CommitPush(
		secretManagementArgs.authorName,
		secretManagementArgs.authorEmail,
		"[configure secret management] Configure secret management using sops and age",
		"",
		secretManagementArgs.fleetBranch,
		rootArgs.timeout,
		status,
	)
	if err != nil {
		return err
	}
	logger.V(0).Infof("Run `kubectl apply -f %s` to apply the secret to the cluster", secretManagementArgs.output)
	return nil
}
