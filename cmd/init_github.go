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

var initGithubCmd = &cobra.Command{
	Use:   "github",
	Short: "",
	Long:  ``,
	RunE:  initGithubCmdRun,
}

type initGithubFlags struct {
	owner       string
	destination string
	personal    bool
	hostname    string
	teams       []string
	reconcile   bool
}

var initGithubArgs initGithubFlags

func init() {
	initGithubCmd.Flags().StringVar(&initGithubArgs.owner, "owner", "", "GitHub user or organization name")
	initGithubCmd.Flags().StringVar(&initGithubArgs.destination, "destination", "", "GitHub repository name where to push the application repository")
	initGithubCmd.Flags().
		StringSliceVar(&initGithubArgs.teams, "team", []string{}, "GitHub team and the access to be given to it(team:maintain). Defaults to maintainer access if no access level is specified (also accepts comma-separated values)")
	initGithubCmd.Flags().BoolVar(&initGithubArgs.personal, "personal", false, "if true, the owner is assumed to be a GitHub user; otherwise an org")
	initGithubCmd.Flags().StringVar(&initGithubArgs.hostname, "hostname", github.DefaultDomain, "GitHub hostname")
	initGithubCmd.Flags().BoolVar(&initGithubArgs.reconcile, "reconcile", false, "if true, the configured options are also reconciled if the repository already exists")

	initCmd.AddCommand(initGithubCmd)
}

func initGithubCmdRun(cmd *cobra.Command, args []string) error {
	logger.V(0).Infof("Initialize the cluster repository...")

	ghToken, err := github.GetToken()
	if err != nil {
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

	// Build GitHub provider
	providerCfg := provider.Config{
		Provider: provider.GitProviderGitHub,
		Hostname: initGithubArgs.hostname,
		Token:    ghToken,
		CaBundle: caBundle,
	}
	providerClient, err := provider.BuildGitProvider(providerCfg)
	if err != nil {
		return err
	}

	clusterRepo, err := repo.CloneClusterRepo(
		&repo.CloneOptions{
			URL:            initArgs.originUrl,
			Branch:         initArgs.originBranch,
			Username:       initGithubArgs.owner,
			Password:       ghToken,
			PrivateKeyFile: initArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			CaBundle:       caBundle,
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
	originUrl, _, err := repo.UniversalURL(initArgs.originUrl)
	if err != nil {
		return err
	}
	clusterRepo.NewClusterConfig(originUrl, head, status)
	destinationUrl, _, err := repo.Create(&repo.CreateOptions{
		RepositoryName: initGithubArgs.destination,
		Owner:          initGithubArgs.owner,
		TransportType:  "https",
		Branch:         initArgs.destinationBranch,
		Timeout:        rootArgs.timeout,
		Personal:       initGithubArgs.personal,
		Reconcile:      initGithubArgs.reconcile,
		Teams:          mapTeamSlice(initGithubArgs.teams, github.DefaultPermission),
		SshHostname:    initArgs.sshHostname,
		Provider:       providerClient,
	}, status)
	if err != nil {
		return err
	}
	clusterRepo.Git().SetAuth(initGithubArgs.owner, ghToken)
	clusterRepo.CommitPush(
		initArgs.authorName,
		initArgs.authorEmail,
		"Initialize cluster repository",
		destinationUrl,
		initArgs.destinationBranch,
		rootArgs.timeout,
		status,
	)
	if err != nil {
		return err
	}
	return nil
}
