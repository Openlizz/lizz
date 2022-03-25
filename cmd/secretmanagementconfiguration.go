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
	"time"

	"github.com/spf13/cobra"

	"gitlab.com/openlizz/lizz/internal/repo"
)

var secretManagementConfigurationCmd = &cobra.Command{
	Use:   "secret-management-configuration",
	Short: "",
	Long:  ``,
	RunE:  secretManagementConfigurationCmdRun,
}

type secretManagementConfigurationFlags struct {
	output           string
	path             string
	decryptionSecret string
	fleetUrl         string
	fleetBranch      string
	interval         time.Duration
	username         string
	password         string
	silent           bool

	authorName  string
	authorEmail string
}

var smcArgs secretManagementConfigurationFlags

func init() {
	secretManagementConfigurationCmd.Flags().StringVarP(&smcArgs.output, "ouput", "o", "sopsAgeSecret.yaml", "output where to save the secret to apply")
	secretManagementConfigurationCmd.Flags().StringVar(&smcArgs.path, "path", "cluster/applications.yaml", "path to the applications yaml file")
	secretManagementConfigurationCmd.Flags().StringVar(&smcArgs.decryptionSecret, "decryptionSecret", "sops-age", "name of the secret containing the AGE secret key")
	secretManagementConfigurationCmd.Flags().StringVar(&smcArgs.fleetUrl, "fleetUrl", "", "Git repository URL of the fleet repository")
	secretManagementConfigurationCmd.Flags().StringVar(&smcArgs.fleetBranch, "fleetBranch", "main", "Git branch of the fleet repository")
	secretManagementConfigurationCmd.Flags().DurationVar(&smcArgs.interval, "interval", time.Minute, "sync interval")
	secretManagementConfigurationCmd.Flags().StringVarP(&smcArgs.username, "username", "u", "git", "basic authentication username")
	secretManagementConfigurationCmd.Flags().StringVarP(&smcArgs.password, "password", "p", "", "basic authentication password")
	secretManagementConfigurationCmd.Flags().BoolVarP(&smcArgs.silent, "silent", "s", false, "assumes the deploy key is already setup, skips confirmation")

	secretManagementConfigurationCmd.Flags().StringVar(&smcArgs.authorName, "author-name", "Lizz", "author name for Git commits")
	secretManagementConfigurationCmd.Flags().StringVar(&smcArgs.authorEmail, "author-email", "", "author email for Git commits")

	rootCmd.AddCommand(secretManagementConfigurationCmd)
}

func secretManagementConfigurationCmdRun(cmd *cobra.Command, args []string) error {
	clusterRepo, err := repo.CloneClusterRepo(smcArgs.fleetUrl, smcArgs.fleetBranch, smcArgs.username, smcArgs.password, rootArgs.timeout)
	if err != nil {
		return err
	}
	err = clusterRepo.OpenClusterConfig()
	if err != nil {
		return err
	}
	err = clusterRepo.ConfigureSecretManagement(smcArgs.decryptionSecret, smcArgs.output, smcArgs.path)
	if err != nil {
		return err
	}
	err = clusterRepo.CommitPush(addArgs.authorName, addArgs.authorEmail, "[configure secret management] Configure secret management using sops and age", "", rootArgs.timeout)
	if err != nil {
		return err
	}
	return nil
}
