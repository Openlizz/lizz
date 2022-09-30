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

	"github.com/spf13/cobra"
	"github.com/openlizz/lizz/internal/github"
	"github.com/openlizz/lizz/internal/provider"
	"github.com/openlizz/lizz/internal/repo"
)

var refreshGithubCmd = &cobra.Command{
	Use:   "github",
	Short: "Refresh an application from GitHub",
	Long:  `The refresh command is used to refresh an application already added to the GitHub cluster. It refreshs the
application configuration with the current cluster state. It can also update the application by using the latest
changes of the application origin GitHub repository.`,
	Example: `# Refresh an application to update its configuration regarding the current cluster state
lizz refresh github --owner=<group>  --fleet=<fleet repository name> --name=<application name>

# Refresh an application and upgrade it
lizz refresh github --owner=<group>  --fleet=<fleet repository name> --name=<application name> --upgrade`,
	RunE:  refreshGithubCmdRun,
}

type refreshGithubFlags struct {
	owner     string
	fleet     string
	personal  bool
	hostname  string
	teams     []string
	reconcile bool
}

var refreshGithubArgs refreshGithubFlags

func init() {
	refreshGithubCmd.Flags().StringVar(&refreshGithubArgs.owner, "owner", "", "GitHub user or organization name")
	refreshGithubCmd.Flags().StringVar(&refreshGithubArgs.fleet, "fleet", "", "GitHub repository name of the fleet repository")
	refreshGithubCmd.Flags().
		StringSliceVar(&refreshGithubArgs.teams, "team", []string{}, "GitHub team and the access to be given to it(team:maintain). Defaults to maintainer access if no access level is specified (also accepts comma-separated values)")
	refreshGithubCmd.Flags().BoolVar(&refreshGithubArgs.personal, "personal", false, "if true, the owner is assumed to be a GitHub user; otherwise an org")
	refreshGithubCmd.Flags().StringVar(&refreshGithubArgs.hostname, "hostname", github.DefaultDomain, "GitHub hostname")
	refreshGithubCmd.Flags().BoolVar(&refreshGithubArgs.reconcile, "reconcile", false, "if true, the configured options are also reconciled if the repository already exists")

	refreshCmd.AddCommand(refreshGithubCmd)
}

func refreshGithubCmdRun(cmd *cobra.Command, args []string) error {
	logger.V(0).Infof("Refresh application...")

	ghToken, err := github.GetToken()
	if err != nil {
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

	// Build GitHub provider
	providerCfg := provider.Config{
		Provider: provider.GitProviderGitHub,
		Hostname: refreshGithubArgs.hostname,
		Token:    ghToken,
		CaBundle: caBundle,
	}
	providerClient, err := provider.BuildGitProvider(providerCfg)
	if err != nil {
		return err
	}

	clusterRepo, err := repo.CloneClusterRepo(
		&repo.CloneOptions{
			RepositoryName: refreshGithubArgs.fleet,
			Owner:          refreshGithubArgs.owner,
			Branch:         refreshArgs.fleetBranch,
			Username:       refreshGithubArgs.owner,
			Password:       ghToken,
			PrivateKeyFile: refreshArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			Personal:       refreshGithubArgs.personal,
			Reconcile:      refreshGithubArgs.reconcile,
			Teams:          mapTeamSlice(refreshGithubArgs.teams, github.DefaultPermission),
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
		Username:       refreshGithubArgs.owner,
		Password:       ghToken,
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
			Username:       refreshGithubArgs.owner,
			Password:       ghToken,
			PrivateKeyFile: refreshArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			Personal:       refreshGithubArgs.personal,
			Reconcile:      refreshGithubArgs.reconcile,
			Teams:          mapTeamSlice(refreshGithubArgs.teams, github.DefaultPermission),
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
	err = applicationRepo.Render(applicationDestinationRepo, refreshGithubArgs.owner, ghToken, status)
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
			Username:       refreshGithubArgs.owner,
			Password:       ghToken,
			PrivateKeyFile: refreshArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			Personal:       refreshGithubArgs.personal,
			Reconcile:      refreshGithubArgs.reconcile,
			Teams:          mapTeamSlice(refreshGithubArgs.teams, github.DefaultPermission),
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
