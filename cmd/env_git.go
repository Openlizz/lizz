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

var envGitCmd = &cobra.Command{
	Use:   "git",
	Short: "",
	Long:  ``,
	RunE:  envGitCmdRun,
}

type envGitFlags struct {
	fleetUrl string
	username string
	password string
}

var envGitArgs envGitFlags

func init() {
	envGitCmd.Flags().StringVar(&envGitArgs.fleetUrl, "fleet-url", "", "Git repository URL of the fleet repository")
	envGitCmd.Flags().StringVarP(&envGitArgs.username, "username", "u", "git", "basic authentication username")
	envGitCmd.Flags().StringVarP(&envGitArgs.password, "password", "p", "", "basic authentication password")

	envCmd.AddCommand(envGitCmd)
}

func envGitCmdRun(cmd *cobra.Command, args []string) error {
	logger.V(0).Infof("Add env variable to the cluster configuration...")

	clusterRepo, err := repo.CloneClusterRepo(
		&repo.CloneOptions{
			URL:            envGitArgs.fleetUrl,
			Branch:         envArgs.fleetBranch,
			Username:       envGitArgs.username,
			Password:       envGitArgs.password,
			PrivateKeyFile: envArgs.privateKeyFile,
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
	err = clusterRepo.AddEnv(envArgs.name, envArgs.value, status)
	if err != nil {
		return err
	}
	err = clusterRepo.CommitPush(
		envArgs.authorName,
		envArgs.authorEmail,
		"[add env variable] Env "+envArgs.name+" added to the cluster configuration",
		"",
		envArgs.fleetBranch,
		rootArgs.timeout,
		status,
	)
	if err != nil {
		return err
	}
	return nil
}
