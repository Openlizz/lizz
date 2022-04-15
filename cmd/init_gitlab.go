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
	"gitlab.com/openlizz/lizz/internal/config"
	"gitlab.com/openlizz/lizz/internal/provider"
	"gitlab.com/openlizz/lizz/internal/repo"
)

var initGitlabCmd = &cobra.Command{
	Use:   "gitlab",
	Short: "",
	Long:  ``,
	RunE:  initGitlabCmdRun,
}

type initGitlabFlags struct {
	owner       string
	destination string
	personal    bool
	hostname    string
	teams       []string
	reconcile   bool
}

var initGitlabArgs initGitlabFlags

func init() {
	initGitlabCmd.Flags().StringVar(&initGitlabArgs.owner, "owner", "", "GitLab user or group name")
	initGitlabCmd.Flags().StringVar(&initGitlabArgs.destination, "destination", "", "GitLab repository name where to push the application repository")
	initGitlabCmd.Flags().StringSliceVar(&initGitlabArgs.teams, "team", []string{}, "GitLab teams to be given maintainer access (also accepts comma-separated values)")
	initGitlabCmd.Flags().BoolVar(&initGitlabArgs.personal, "personal", false, "if true, the owner is assumed to be a GitLab user; otherwise a group")
	initGitlabCmd.Flags().StringVar(&initGitlabArgs.hostname, "hostname", glDefaultDomain, "GitLab hostname")
	initGitlabCmd.Flags().BoolVar(&initGitlabArgs.reconcile, "reconcile", false, "if true, the configured options are also reconciled if the repository already exists")

	initCmd.AddCommand(initGitlabCmd)
}

func initGitlabCmdRun(cmd *cobra.Command, args []string) error {
	logger.V(0).Infof("Initialize the cluster repository...")

	glToken := os.Getenv(glTokenEnvVar)
	if glToken == "" {
		var err error
		glToken, err = readPasswordFromStdin("Please enter your GitLab personal access token (PAT): ")
		if err != nil {
			return fmt.Errorf("could not read token: %w", err)
		}
	}

	if projectNameIsValid, err := regexp.MatchString(gitlabProjectRegex, initGitlabArgs.destination); err != nil || !projectNameIsValid {
		if err == nil {
			err = fmt.Errorf(
				"%s is an invalid project name for gitlab.\nIt can contain only letters, digits, emojis, '_', '.', dash, space. It must start with letter, digit, emoji or '_'.",
				initGitlabArgs.destination,
			)
		}
		return err
	}

	var caBundle []byte
	if initArgs.caFile != "" {
		var err error
		caBundle, err = os.ReadFile(initArgs.caFile)
		if err != nil {
			return fmt.Errorf("unable to read TLS CA file: %w", err)
		}
	}

	// Build GitLab provider
	providerCfg := provider.Config{
		Provider: provider.GitProviderGitLab,
		Hostname: addGitlabArgs.hostname,
		Token:    glToken,
		CaBundle: caBundle,
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
			URL:      initArgs.originUrl,
			Branch:   initArgs.originBranch,
			Username: initGitlabArgs.owner,
			Password: glToken,
			Timeout:  rootArgs.timeout,
			CaBundle: caBundle,
		},
		status,
	)
	if err != nil {
		return err
	}
	head, err := clusterRepo.Git().Head()
	if err != nil {
		return err
	}
	originUrl, err := config.UniversalURL(initArgs.originUrl)
	if err != nil {
		return err
	}
	clusterRepo.NewClusterConfig(originUrl, head, status)
	destinationUrl, _, err := repo.Create(&repo.CreateOptions{
		RepositoryName: initGitlabArgs.destination,
		Owner:          initGitlabArgs.owner,
		TransportType:  "https",
		Branch:         initArgs.destinationBranch,
		Timeout:        rootArgs.timeout,
		Personal:       initGitlabArgs.personal,
		Reconcile:      initGitlabArgs.reconcile,
		Teams:          mapTeamSlice(initGitlabArgs.teams, glDefaultPermission),
		SshHostname:    addArgs.sshHostname,
		Provider:       providerClient,
	}, status)
	if err != nil {
		return err
	}
	clusterRepo.Git().SetAuth(initGitlabArgs.owner, glToken)
	clusterRepo.CommitPush(
		initArgs.authorName,
		initArgs.authorEmail,
		"Initialize cluster repository",
		destinationUrl,
		rootArgs.timeout,
		status,
	)
	if err != nil {
		return err
	}
	return nil
}
