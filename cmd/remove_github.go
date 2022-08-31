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
	"gitlab.com/openlizz/lizz/internal/github"
	"gitlab.com/openlizz/lizz/internal/provider"
	"gitlab.com/openlizz/lizz/internal/repo"
)

var removeGithubCmd = &cobra.Command{
	Use:   "github",
	Short: "",
	Long:  ``,
	RunE:  removeGithubCmdRun,
}

type removeGithubFlags struct {
	owner     string
	fleet     string
	personal  bool
	hostname  string
	teams     []string
	reconcile bool
}

var removeGithubArgs removeGithubFlags

func init() {
	removeGithubCmd.Flags().StringVar(&removeGithubArgs.owner, "owner", "", "GitHub user or organization name")
	removeGithubCmd.Flags().StringVar(&removeGithubArgs.fleet, "fleet", "", "GitHub repository name of the fleet repository")
	removeGithubCmd.Flags().
		StringSliceVar(&removeGithubArgs.teams, "team", []string{}, "GitHub team and the access to be given to it(team:maintain). Defaults to maintainer access if no access level is specified (also accepts comma-separated values)")
	removeGithubCmd.Flags().BoolVar(&removeGithubArgs.personal, "personal", false, "if true, the owner is assumed to be a GitHub user; otherwise an org")
	removeGithubCmd.Flags().StringVar(&removeGithubArgs.hostname, "hostname", github.DefaultDomain, "GitHub hostname")
	removeGithubCmd.Flags().BoolVar(&removeGithubArgs.reconcile, "reconcile", false, "if true, the configured options are also reconciled if the repository already exists")

	removeCmd.AddCommand(removeGithubCmd)
}

func removeGithubCmdRun(cmd *cobra.Command, args []string) error {
	logger.V(0).Infof("Remove application...")

	ghToken, err := github.GetToken()
	if err != nil {
		return err
	}

	// Build GitHub provider
	providerCfg := provider.Config{
		Provider: provider.GitProviderGitHub,
		Hostname: removeGithubArgs.hostname,
		Token:    ghToken,
	}
	providerClient, err := provider.BuildGitProvider(providerCfg)
	if err != nil {
		return err
	}

	clusterRepo, err := repo.CloneClusterRepo(
		&repo.CloneOptions{
			RepositoryName: removeGithubArgs.fleet,
			Owner:          removeGithubArgs.owner,
			Branch:         removeArgs.fleetBranch,
			Username:       removeGithubArgs.owner,
			Password:       ghToken,
			PrivateKeyFile: removeArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			Personal:       removeGithubArgs.personal,
			Reconcile:      removeGithubArgs.reconcile,
			Teams:          mapTeamSlice(removeGithubArgs.teams, github.DefaultPermission),
			Provider:       providerClient,
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
