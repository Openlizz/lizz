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

var removeGitlabCmd = &cobra.Command{
	Use:   "gitlab",
	Short: "",
	Long:  ``,
	RunE:  removeGitlabCmdRun,
}

type removeGitlabFlags struct {
	owner     string
	fleet     string
	personal  bool
	hostname  string
	teams     []string
	reconcile bool
}

var removeGitlabArgs removeGitlabFlags

func init() {
	removeGitlabCmd.Flags().StringVar(&removeGitlabArgs.owner, "owner", "", "GitLab user or group name")
	removeGitlabCmd.Flags().StringVar(&removeGitlabArgs.fleet, "fleet", "", "GitLab repository name where to push the application repository")
	removeGitlabCmd.Flags().StringSliceVar(&removeGitlabArgs.teams, "team", []string{}, "GitLab teams to be given maintainer access (also accepts comma-separated values)")
	removeGitlabCmd.Flags().BoolVar(&removeGitlabArgs.personal, "personal", false, "if true, the owner is assumed to be a GitLab user; otherwise a group")
	removeGitlabCmd.Flags().StringVar(&removeGitlabArgs.hostname, "hostname", glDefaultDomain, "GitLab hostname")
	removeGitlabCmd.Flags().BoolVar(&removeGitlabArgs.reconcile, "reconcile", false, "if true, the configured options are also reconciled if the repository already exists")

	removeCmd.AddCommand(removeGitlabCmd)
}

func removeGitlabCmdRun(cmd *cobra.Command, args []string) error {
	glToken := os.Getenv(glTokenEnvVar)
	if glToken == "" {
		var err error
		glToken, err = readPasswordFromStdin("Please enter your GitLab personal access token (PAT): ")
		if err != nil {
			return fmt.Errorf("could not read token: %w", err)
		}
	}

	if projectNameIsValid, err := regexp.MatchString(gitlabProjectRegex, removeGitlabArgs.fleet); err != nil || !projectNameIsValid {
		if err == nil {
			err = fmt.Errorf(
				"%s is an invalid project name for gitlab.\nIt can contain only letters, digits, emojis, '_', '.', dash, space. It must start with letter, digit, emoji or '_'.",
				removeGitlabArgs.fleet,
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
			RepositoryName: removeGitlabArgs.fleet,
			Owner:          removeGitlabArgs.owner,
			Branch:         removeArgs.fleetBranch,
			Username:       removeGitlabArgs.owner,
			Password:       glToken,
			Timeout:        rootArgs.timeout,
			Personal:       removeGitlabArgs.personal,
			Reconcile:      removeGitlabArgs.reconcile,
			Teams:          mapTeamSlice(removeGitlabArgs.teams, glDefaultPermission),
			Provider:       providerClient,
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
