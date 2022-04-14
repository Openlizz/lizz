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

var secretManagementCmd = &cobra.Command{
	Use:   "secret-management",
	Short: "",
	Long:  ``,
	RunE:  secretManagementCmdRun,
}

type secretManagementFlags struct {
	output           string
	path             string
	decryptionSecret string
	fleetUrl         string
	fleetBranch      string
	username         string
	password         string
	privateKeyFile   string

	authorName  string
	authorEmail string
}

var secretManagementArgs secretManagementFlags

func init() {
	secretManagementCmd.Flags().StringVarP(&secretManagementArgs.output, "ouput", "o", "sopsAgeSecret.yaml", "output where to save the secret to apply")
	secretManagementCmd.Flags().StringVar(&secretManagementArgs.path, "path", "cluster/applications.yaml", "path to the applications yaml file")
	secretManagementCmd.Flags().StringVar(&secretManagementArgs.decryptionSecret, "decryption-secret", "sops-age", "name of the secret containing the AGE secret key")
	secretManagementCmd.Flags().StringVar(&secretManagementArgs.fleetUrl, "fleet-url", "", "Git repository URL of the fleet repository")
	secretManagementCmd.Flags().StringVar(&secretManagementArgs.fleetBranch, "fleet-branch", "main", "Git branch of the fleet repository")
	secretManagementCmd.Flags().StringVarP(&secretManagementArgs.username, "username", "u", "git", "basic authentication username")
	secretManagementCmd.Flags().StringVarP(&secretManagementArgs.password, "password", "p", "", "basic authentication password")
	secretManagementCmd.Flags().StringVar(&secretManagementArgs.privateKeyFile, "private-key-file", "", "path to a private key file used for authenticating to the Git SSH server")

	secretManagementCmd.Flags().StringVar(&secretManagementArgs.authorName, "author-name", "Lizz", "author name for Git commits")
	secretManagementCmd.Flags().StringVar(&secretManagementArgs.authorEmail, "author-email", "", "author email for Git commits")

	rootCmd.AddCommand(secretManagementCmd)
}

func secretManagementCmdRun(cmd *cobra.Command, args []string) error {
	clusterRepo, err := repo.CloneClusterRepo(
		secretManagementArgs.fleetUrl,
		secretManagementArgs.fleetBranch,
		secretManagementArgs.username,
		secretManagementArgs.password,
		secretManagementArgs.privateKeyFile,
		rootArgs.timeout,
	)
	if err != nil {
		return err
	}
	err = clusterRepo.OpenClusterConfig()
	if err != nil {
		return err
	}
	err = clusterRepo.ConfigureSecretManagement(
		secretManagementArgs.decryptionSecret,
		secretManagementArgs.output,
		secretManagementArgs.path,
	)
	if err != nil {
		return err
	}
	err = clusterRepo.CommitPush(
		addArgs.authorName,
		addArgs.authorEmail,
		"[configure secret management] Configure secret management using sops and age",
		"",
		rootArgs.timeout,
	)
	if err != nil {
		return err
	}
	return nil
}
