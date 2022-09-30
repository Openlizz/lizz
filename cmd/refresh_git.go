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
	"github.com/openlizz/lizz/internal/repo"
)

var refreshGitCmd = &cobra.Command{
	Use:   "git",
	Short: "Refresh an application from any Git server",
	Long:  `The refresh command is used to refresh an application already added to the Git cluster. It refreshs the
application configuration with the current cluster state. It can also update the application by using the latest
changes of the application origin Git repository.`,
	RunE:  refreshGitCmdRun,
}

type refreshGitFlags struct {
	fleetUrl string
	username string
	password string
	silent   bool
}

var refreshGitArgs refreshGitFlags

func init() {
	refreshGitCmd.Flags().StringVar(&refreshGitArgs.fleetUrl, "fleet-url", "", "Git repository URL of the fleet repository")
	refreshGitCmd.Flags().StringVarP(&refreshGitArgs.username, "username", "u", "git", "basic authentication username")
	refreshGitCmd.Flags().StringVarP(&refreshGitArgs.password, "password", "p", "", "basic authentication password")
	refreshGitCmd.Flags().BoolVarP(&refreshGitArgs.silent, "silent", "s", false, "assumes the deploy key is already setup, skips confirmation")

	refreshCmd.AddCommand(refreshGitCmd)
}

func refreshGitCmdRun(cmd *cobra.Command, args []string) error {
	logger.V(0).Infof("Refresh application...")

	var caBundle []byte
	if refreshArgs.caFile != "" {
		var err error
		caBundle, err = os.ReadFile(refreshArgs.caFile)
		if err != nil {
			return fmt.Errorf("unable to read TLS CA file: %w", err)
		}
	}

	clusterRepo, err := repo.CloneClusterRepo(
		&repo.CloneOptions{
			URL:            refreshGitArgs.fleetUrl,
			Branch:         refreshArgs.fleetBranch,
			Username:       refreshGitArgs.username,
			Password:       refreshGitArgs.password,
			PrivateKeyFile: refreshArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			CaBundle:       caBundle,
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
		Username:       refreshGitArgs.username,
		Password:       refreshGitArgs.password,
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
			Username:       refreshGitArgs.username,
			Password:       refreshGitArgs.password,
			PrivateKeyFile: refreshArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			CaBundle:       caBundle,
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
	err = applicationRepo.Render(applicationDestinationRepo, refreshGitArgs.username, refreshGitArgs.password, status)
	if err != nil {
		return err
	}
	err = applicationRepo.Encrypt(clusterRepo.Config(), status)
	if err != nil {
		return err
	}
	destinationApplicationRepo, err := repo.CloneApplicationRepo(
		&repo.CloneOptions{
			URL:            applicationDestinationRepo.URL,
			Username:       refreshGitArgs.username,
			Password:       refreshGitArgs.password,
			PrivateKeyFile: refreshArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			CaBundle:       caBundle,
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
