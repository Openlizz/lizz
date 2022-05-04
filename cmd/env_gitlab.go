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

var envGitlabCmd = &cobra.Command{
	Use:   "gitlab",
	Short: "",
	Long:  ``,
	RunE:  envGitlabCmdRun,
}

type envGitlabFlags struct {
	owner     string
	fleet     string
	personal  bool
	hostname  string
	teams     []string
	reconcile bool
}

var envGitlabArgs envGitlabFlags

func init() {
	envGitlabCmd.Flags().StringVar(&envGitlabArgs.owner, "owner", "", "GitLab user or group name")
	envGitlabCmd.Flags().StringVar(&envGitlabArgs.fleet, "fleet", "", "GitLab repository name where to push the application repository")
	envGitlabCmd.Flags().StringSliceVar(&envGitlabArgs.teams, "team", []string{}, "GitLab teams to be given maintainer access (also accepts comma-separated values)")
	envGitlabCmd.Flags().BoolVar(&envGitlabArgs.personal, "personal", false, "if true, the owner is assumed to be a GitLab user; otherwise a group")
	envGitlabCmd.Flags().StringVar(&envGitlabArgs.hostname, "hostname", glDefaultDomain, "GitLab hostname")
	envGitlabCmd.Flags().BoolVar(&envGitlabArgs.reconcile, "reconcile", false, "if true, the configured options are also reconciled if the repository already exists")

	envCmd.AddCommand(envGitlabCmd)
}

func envGitlabCmdRun(cmd *cobra.Command, args []string) error {
	logger.V(0).Infof("Add env variable to the cluster configuration...")

	glToken := os.Getenv(glTokenEnvVar)
	if glToken == "" {
		var err error
		glToken, err = readPasswordFromStdin("Please enter your GitLab personal access token (PAT): ")
		if err != nil {
			return fmt.Errorf("could not read token: %w", err)
		}
	}

	if projectNameIsValid, err := regexp.MatchString(gitlabProjectRegex, envGitlabArgs.fleet); err != nil || !projectNameIsValid {
		if err == nil {
			err = fmt.Errorf(
				"%s is an invalid project name for gitlab.\nIt can contain only letters, digits, emojis, '_', '.', dash, space. It must start with letter, digit, emoji or '_'.",
				envGitlabArgs.fleet,
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

	clusterRepo, err := repo.CloneClusterRepo(
		&repo.CloneOptions{
			RepositoryName: envGitlabArgs.fleet,
			Owner:          envGitlabArgs.owner,
			Branch:         removeArgs.fleetBranch,
			Username:       envGitlabArgs.owner,
			Password:       glToken,
			Timeout:        rootArgs.timeout,
			Personal:       envGitlabArgs.personal,
			Reconcile:      envGitlabArgs.reconcile,
			Teams:          mapTeamSlice(envGitlabArgs.teams, glDefaultPermission),
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
	err = clusterRepo.AddEnv(envArgs.name, envArgs.value, status)
	if err != nil {
		return err
	}
	err = clusterRepo.CommitPush(
		removeArgs.authorName,
		removeArgs.authorEmail,
		"[add env variable] Env "+envArgs.name+" added to the cluster configuration",
		"",
		rootArgs.timeout,
		status,
	)
	if err != nil {
		return err
	}
	return nil
}
