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
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"gitlab.com/openlizz/lizz/internal/provider"
	"gitlab.com/openlizz/lizz/internal/repo"
)

var secretManagementGitlabCmd = &cobra.Command{
	Use:   "gitlab",
	Short: "",
	Long:  ``,
	RunE:  secretManagementGitlabCmdRun,
}

type secretManagementGitlabFlags struct {
	owner     string
	fleet     string
	personal  bool
	hostname  string
	teams     []string
	reconcile bool
}

var secretManagementGitlabArgs secretManagementGitlabFlags

func init() {
	secretManagementGitlabCmd.Flags().StringVar(&secretManagementGitlabArgs.owner, "owner", "", "GitLab user or group name")
	secretManagementGitlabCmd.Flags().StringVar(&secretManagementGitlabArgs.fleet, "fleet", "", "GitLab repository name where to push the application repository")
	secretManagementGitlabCmd.Flags().StringSliceVar(&secretManagementGitlabArgs.teams, "team", []string{}, "GitLab teams to be given maintainer access (also accepts comma-separated values)")
	secretManagementGitlabCmd.Flags().BoolVar(&secretManagementGitlabArgs.personal, "personal", false, "if true, the owner is assumed to be a GitLab user; otherwise a group")
	secretManagementGitlabCmd.Flags().StringVar(&secretManagementGitlabArgs.hostname, "hostname", glDefaultDomain, "GitLab hostname")
	secretManagementGitlabCmd.Flags().BoolVar(&secretManagementGitlabArgs.reconcile, "reconcile", false, "if true, the configured options are also reconciled if the repository already exists")

	secretManagementCmd.AddCommand(secretManagementGitlabCmd)
}

func secretManagementGitlabCmdRun(cmd *cobra.Command, args []string) error {
	glToken := os.Getenv(glTokenEnvVar)
	if glToken == "" {
		var err error
		glToken, err = readPasswordFromStdin("Please enter your GitLab personal access token (PAT): ")
		if err != nil {
			return fmt.Errorf("could not read token: %w", err)
		}
	}

	if projectNameIsValid, err := regexp.MatchString(gitlabProjectRegex, secretManagementGitlabArgs.fleet); err != nil || !projectNameIsValid {
		if err == nil {
			err = fmt.Errorf(
				"%s is an invalid project name for gitlab.\nIt can contain only letters, digits, emojis, '_', '.', dash, space. It must start with letter, digit, emoji or '_'.",
				secretManagementGitlabArgs.fleet,
			)
		}
		return err
	}

	// Build GitLab provider
	providerCfg := provider.Config{
		Provider: provider.GitProviderGitLab,
		Hostname: addGitlabArgs.hostname,
		Token:    glToken,
	}
	// Workaround for: https://github.com/fluxcd/go-git-providers/issues/55
	if hostname := providerCfg.Hostname; hostname != glDefaultDomain &&
		!strings.HasPrefix(hostname, "https://") &&
		!strings.HasPrefix(hostname, "http://") {
		providerCfg.Hostname = "https://" + providerCfg.Hostname
	}
	providerClient, err := provider.BuildGitProvider(providerCfg)
	if err != nil {
		return err
	}

	logger.Actionf("Clone the fleet repository.")
	clusterRepo, err := repo.CloneClusterRepo(
		&repo.CloneOptions{
			RepositoryName: secretManagementGitlabArgs.fleet,
			Owner:          secretManagementGitlabArgs.owner,
			Branch:         secretManagementArgs.fleetBranch,
			Username:       secretManagementGitlabArgs.owner,
			Password:       glToken,
			Timeout:        rootArgs.timeout,
			Personal:       secretManagementGitlabArgs.personal,
			Reconcile:      secretManagementGitlabArgs.reconcile,
			Teams:          mapTeamSlice(secretManagementGitlabArgs.teams, glDefaultPermission),
			Provider:       providerClient,
		},
	)
	if err != nil {
		return err
	}
	logger.Successf("")
	logger.Actionf("Configure the secret management.")
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
	logger.Successf("")
	logger.Actionf("Commit and push to the fleet repository.")
	err = clusterRepo.CommitPush(
		secretManagementArgs.authorName,
		secretManagementArgs.authorEmail,
		"[configure secret management] Configure secret management using sops and age",
		"",
		rootArgs.timeout,
	)
	if err != nil {
		return err
	}
	logger.Successf("")
	return nil
}
