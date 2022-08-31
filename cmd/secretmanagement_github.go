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

var secretManagementGithubCmd = &cobra.Command{
	Use:   "github",
	Short: "",
	Long:  ``,
	RunE:  secretManagementGithubCmdRun,
}

type secretManagementGithubFlags struct {
	owner     string
	fleet     string
	personal  bool
	hostname  string
	teams     []string
	reconcile bool
}

var secretManagementGithubArgs secretManagementGithubFlags

func init() {
	secretManagementGithubCmd.Flags().StringVar(&secretManagementGithubArgs.owner, "owner", "", "GitHub user or organization name")
	secretManagementGithubCmd.Flags().StringVar(&secretManagementGithubArgs.fleet, "fleet", "", "GitHub repository name of the fleet repository")
	secretManagementGithubCmd.Flags().
		StringSliceVar(&secretManagementGithubArgs.teams, "team", []string{}, "GitHub team and the access to be given to it(team:maintain). Defaults to maintainer access if no access level is specified (also accepts comma-separated values)")
	secretManagementGithubCmd.Flags().BoolVar(&secretManagementGithubArgs.personal, "personal", false, "f true, the owner is assumed to be a GitHub user; otherwise an org")
	secretManagementGithubCmd.Flags().StringVar(&secretManagementGithubArgs.hostname, "hostname", github.DefaultDomain, "GitHub hostname")
	secretManagementGithubCmd.Flags().BoolVar(&secretManagementGithubArgs.reconcile, "reconcile", false, "if true, the configured options are also reconciled if the repository already exists")

	secretManagementCmd.AddCommand(secretManagementGithubCmd)
}

func secretManagementGithubCmdRun(cmd *cobra.Command, args []string) error {
	logger.V(0).Infof("Configure secret management...")

	ghToken, err := github.GetToken()
	if err != nil {
		return err
	}

	// Build GitHub provider
	providerCfg := provider.Config{
		Provider: provider.GitProviderGitHub,
		Hostname: secretManagementGithubArgs.hostname,
		Token:    ghToken,
	}
	providerClient, err := provider.BuildGitProvider(providerCfg)
	if err != nil {
		return err
	}

	clusterRepo, err := repo.CloneClusterRepo(
		&repo.CloneOptions{
			RepositoryName: secretManagementGithubArgs.fleet,
			Owner:          secretManagementGithubArgs.owner,
			Branch:         secretManagementArgs.fleetBranch,
			Username:       secretManagementGithubArgs.owner,
			Password:       ghToken,
			PrivateKeyFile: secretManagementArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			Personal:       secretManagementGithubArgs.personal,
			Reconcile:      secretManagementGithubArgs.reconcile,
			Teams:          mapTeamSlice(secretManagementGithubArgs.teams, github.DefaultPermission),
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
