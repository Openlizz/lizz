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
	"github.com/openlizz/lizz/internal/gitlab"
	"github.com/openlizz/lizz/internal/provider"
	"github.com/openlizz/lizz/internal/repo"
)

var refreshGitlabCmd = &cobra.Command{
	Use:   "gitlab",
	Short: "Refresh an application from GitLab",
	Long:  `The refresh command is used to refresh an application already added to the GitLab cluster. It refreshs the
application configuration with the current cluster state. It can also update the application by using the latest
changes of the application origin GitLab repository.`,
	Example: `# Refresh an application to update its configuration regarding the current cluster state
lizz refresh gitlab --owner=<group>  --fleet=<fleet repository name> --name=<application name>

# Refresh an application and upgrade it
lizz refresh gitlab --owner=<group>  --fleet=<fleet repository name> --name=<application name> --upgrade`,
	RunE:  refreshGitlabCmdRun,
}

type refreshGitlabFlags struct {
	owner     string
	fleet     string
	personal  bool
	hostname  string
	teams     []string
	reconcile bool
}

var refreshGitlabArgs refreshGitlabFlags

func init() {
	refreshGitlabCmd.Flags().StringVar(&refreshGitlabArgs.owner, "owner", "", "GitLab user or group name")
	refreshGitlabCmd.Flags().StringVar(&refreshGitlabArgs.fleet, "fleet", "", "GitLab repository name where to push the application repository")
	refreshGitlabCmd.Flags().StringSliceVar(&refreshGitlabArgs.teams, "team", []string{}, "GitLab teams to be given maintainer access (also accepts comma-separated values)")
	refreshGitlabCmd.Flags().BoolVar(&refreshGitlabArgs.personal, "personal", false, "if true, the owner is assumed to be a GitLab user; otherwise a group")
	refreshGitlabCmd.Flags().StringVar(&refreshGitlabArgs.hostname, "hostname", gitlab.DefaultDomain, "GitLab hostname")
	refreshGitlabCmd.Flags().BoolVar(&refreshGitlabArgs.reconcile, "reconcile", false, "if true, the configured options are also reconciled if the repository already exists")

	refreshCmd.AddCommand(refreshGitlabCmd)
}

func refreshGitlabCmdRun(cmd *cobra.Command, args []string) error {
	logger.V(0).Infof("Refresh application...")

	glToken, err := gitlab.GetToken()
	if err != nil {
		return err
	}

	if projectNameIsValid, err := regexp.MatchString(gitlab.ProjectRegex, refreshGitlabArgs.fleet); err != nil || !projectNameIsValid {
		if err == nil {
			err = fmt.Errorf(
				"%s is an invalid project name for gitlab.\nIt can contain only letters, digits, emojis, '_', '.', dash, space. It must start with letter, digit, emoji or '_'.",
				refreshGitlabArgs.fleet,
			)
		}
		return err
	}

	var caBundle []byte
	if refreshArgs.caFile != "" {
		var err error
		caBundle, err = os.ReadFile(refreshArgs.caFile)
		if err != nil {
			return fmt.Errorf("unable to read TLS CA file: %w", err)
		}
	}

	// Build GitLab provider
	providerCfg := provider.Config{
		Provider: provider.GitProviderGitLab,
		Hostname: refreshGitlabArgs.hostname,
		Token:    glToken,
		CaBundle: caBundle,
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
			RepositoryName: refreshGitlabArgs.fleet,
			Owner:          refreshGitlabArgs.owner,
			Branch:         refreshArgs.fleetBranch,
			Username:       refreshGitlabArgs.owner,
			Password:       glToken,
			PrivateKeyFile: refreshArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			Personal:       refreshGitlabArgs.personal,
			Reconcile:      refreshGitlabArgs.reconcile,
			Teams:          mapTeamSlice(refreshGitlabArgs.teams, gitlab.DefaultPermission),
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
	applicationConfig, err := clusterRepo.Config().GetApplicationConfig(refreshArgs.applicationName)
	if err != nil {
		return err
	}
	url, err := applicationConfig.GetUrl()
	if err != nil {
		return err
	}
	applicationCloneOptions := &repo.CloneOptions{
		URL:            url,
		Username:       refreshGitlabArgs.owner,
		Password:       glToken,
		PrivateKeyFile: refreshArgs.privateKeyFile,
		Timeout:        rootArgs.timeout,
		CaBundle:       caBundle,
	}
	if refreshArgs.upgrade == true {
		applicationCloneOptions.Branch = refreshArgs.originBranch
	} else {
		sha, err := applicationConfig.GetSha()
		if err != nil {
			return err
		}
		applicationCloneOptions.Sha = sha
	}
	applicationRepo, err := repo.CloneApplicationRepo(
		applicationCloneOptions,
		status,
	)
	if err != nil {
		return err
	}
	head, err := applicationRepo.Git().Head()
	if err != nil {
		return fmt.Errorf("error when getting the head of the application repository: %w", err)
	}
	err = applicationRepo.RenderApplicationConfig(
		refreshArgs.values,
		clusterRepo.Config(),
		&repo.CloneOptions{
			Username:       refreshGitlabArgs.owner,
			Password:       glToken,
			PrivateKeyFile: refreshArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			Personal:       refreshGitlabArgs.personal,
			Reconcile:      refreshGitlabArgs.reconcile,
			Teams:          mapTeamSlice(refreshGitlabArgs.teams, gitlab.DefaultPermission),
			CaBundle:       caBundle,
			SshHostname:    refreshArgs.sshHostname,
			Provider:       providerClient,
		},
		status,
	)
	if err != nil {
		return err
	}
	applicationRepo.Config().Name = applicationConfig.Name
	applicationRepo.Config().Namespace = applicationConfig.Namespace
	applicationRepo.Config().Repository = applicationConfig.Repository
	applicationRepo.Config().Sha = head
	alreadyInstalled := true
	err = applicationRepo.Config().Check(clusterRepo.Config(), alreadyInstalled, status)
	if err != nil {
		return err
	}
	applicationDestinationRepo, err := clusterRepo.Config().GetApplicationRepository(refreshArgs.applicationName)
	if err != nil {
		return err
	}
	if refreshArgs.path != "" {
		applicationDestinationRepo.Path = refreshArgs.path
	}
	err = applicationRepo.Render(applicationDestinationRepo, refreshGitlabArgs.owner, glToken, status)
	if err != nil {
		return err
	}
	err = applicationRepo.Encrypt(clusterRepo.Config(), status)
	if err != nil {
		return err
	}
	destinationApplicationRepo, err := repo.CloneApplicationRepo(
		&repo.CloneOptions{
			RepositoryName: applicationDestinationRepo.Name,
			Owner:          applicationDestinationRepo.Owner,
			Branch:         applicationDestinationRepo.Branch,
			Username:       refreshGitlabArgs.owner,
			Password:       glToken,
			PrivateKeyFile: refreshArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			Personal:       refreshGitlabArgs.personal,
			Reconcile:      refreshGitlabArgs.reconcile,
			Teams:          mapTeamSlice(refreshGitlabArgs.teams, gitlab.DefaultPermission),
			CaBundle:       caBundle,
			SshHostname:    refreshArgs.sshHostname,
			Provider:       providerClient,
		},
		status,
	)
	if err != nil {
		return err
	}
	err = destinationApplicationRepo.GetFilesFromAnotherRepo(applicationRepo)
	if err != nil {
		return err
	}
	err = destinationApplicationRepo.CommitPush(
		refreshArgs.authorName,
		refreshArgs.authorEmail,
		"[refresh application] Refresh application repository for "+applicationRepo.Config().Name,
		"",
		applicationDestinationRepo.Branch,
		rootArgs.timeout,
		status,
	)
	if err != nil {
		return err
	}

	err = clusterRepo.RefreshApplication(refreshArgs.applicationName, applicationRepo.Config(), status)
	if err != nil {
		return err
	}
	err = clusterRepo.CommitPush(
		refreshArgs.authorName,
		refreshArgs.authorEmail,
		"[refresh application] Refresh "+refreshArgs.applicationName+" from the cluster",
		"",
		refreshArgs.fleetBranch,
		rootArgs.timeout,
		status,
	)
	if err != nil {
		return err
	}
	return nil
}
