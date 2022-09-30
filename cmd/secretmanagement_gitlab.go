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
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/openlizz/lizz/internal/gitlab"
	"github.com/openlizz/lizz/internal/provider"
	"github.com/openlizz/lizz/internal/repo"
)

var secretManagementGitlabCmd = &cobra.Command{
	Use:   "gitlab",
	Short: "Configure secret management for GitLab",
	Long:  `The secret-management command is used to configure Kubernetes secrets management with Mozilla SOPS. It generates a age key, store the public key in the GitLab fleet repository, and store the private key in a yaml file to apply it.`,
	Example: `# Configure secret management
lizz secret-management gitlab --owner=<group>  --fleet=<fleet repository name>
kubectl apply -f secret.yaml`,
	RunE: secretManagementGitlabCmdRun,
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
	secretManagementGitlabCmd.Flags().StringVar(&secretManagementGitlabArgs.hostname, "hostname", gitlab.DefaultDomain, "GitLab hostname")
	secretManagementGitlabCmd.Flags().BoolVar(&secretManagementGitlabArgs.reconcile, "reconcile", false, "if true, the configured options are also reconciled if the repository already exists")

	secretManagementCmd.AddCommand(secretManagementGitlabCmd)
}

func secretManagementGitlabCmdRun(cmd *cobra.Command, args []string) error {
	logger.V(0).Infof("Configure secret management...")

	glToken, err := gitlab.GetToken()
	if err != nil {
		return err
	}

	if projectNameIsValid, err := regexp.MatchString(gitlab.ProjectRegex, secretManagementGitlabArgs.fleet); err != nil || !projectNameIsValid {
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
		Hostname: secretManagementGitlabArgs.hostname,
		Token:    glToken,
	}
	// Workaround for: https://github.com/fluxcd/go-git-providers/issues/55
	if hostname := providerCfg.Hostname; hostname != gitlab.DefaultDomain &&
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
			RepositoryName: secretManagementGitlabArgs.fleet,
			Owner:          secretManagementGitlabArgs.owner,
			Branch:         secretManagementArgs.fleetBranch,
			Username:       secretManagementGitlabArgs.owner,
			Password:       glToken,
			PrivateKeyFile: secretManagementArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			Personal:       secretManagementGitlabArgs.personal,
			Reconcile:      secretManagementGitlabArgs.reconcile,
			Teams:          mapTeamSlice(secretManagementGitlabArgs.teams, gitlab.DefaultPermission),
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
