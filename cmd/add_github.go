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
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/openlizz/lizz/internal/github"
	"github.com/openlizz/lizz/internal/provider"
	"github.com/openlizz/lizz/internal/repo"
	"github.com/openlizz/lizz/internal/yaml"
)

var addGithubCmd = &cobra.Command{
	Use:   "github",
	Short: "",
	Long:  ``,
	RunE:  addGithubCmdRun,
}

type addGithubFlags struct {
	owner        string
	fleet        string
	destination  string
	interval     time.Duration
	personal     bool
	hostname     string
	teams        []string
	readWriteKey bool
	reconcile    bool
}

var addGithubArgs addGithubFlags

func init() {
	addGithubCmd.Flags().StringVar(&addGithubArgs.owner, "owner", "", "GitHub user or organization name")
	addGithubCmd.Flags().StringVar(&addGithubArgs.fleet, "fleet", "", "GitHub repository name of the fleet repository")
	addGithubCmd.Flags().StringVar(&addGithubArgs.destination, "destination", "", "GitHub repository name where to push the application repository")
	addGithubCmd.Flags().
		StringSliceVar(&addGithubArgs.teams, "team", []string{}, "GitHub team and the access to be given to it(team:maintain). Defaults to maintainer access if no access level is specified (also accepts comma-separated values)")
	addGithubCmd.Flags().BoolVar(&addGithubArgs.personal, "personal", false, "if true, the owner is assumed to be a GitHub user; otherwise an org")
	addGithubCmd.Flags().DurationVar(&addGithubArgs.interval, "interval", time.Minute, "sync interval")
	addGithubCmd.Flags().StringVar(&addGithubArgs.hostname, "hostname", github.DefaultDomain, "GitHub hostname")
	addGithubCmd.Flags().BoolVar(&addGithubArgs.readWriteKey, "read-write-key", false, "if true, the deploy key is configured with read/write permissions")
	addGithubCmd.Flags().BoolVar(&addGithubArgs.reconcile, "reconcile", false, "if true, the configured options are also reconciled if the repository already exists")

	addCmd.AddCommand(addGithubCmd)
}

func addGithubCmdRun(cmd *cobra.Command, args []string) error {
	logger.V(0).Infof("Add new application...")

	ghToken, err := github.GetToken()
	if err != nil {
		return err
	}

	var caBundle []byte
	if addArgs.caFile != "" {
		var err error
		caBundle, err = os.ReadFile(addArgs.caFile)
		if err != nil {
			return fmt.Errorf("unable to read TLS CA file: %w", err)
		}
	}

	// Build GitHub provider
	providerCfg := provider.Config{
		Provider: provider.GitProviderGitHub,
		Hostname: addGithubArgs.hostname,
		Token:    ghToken,
		CaBundle: caBundle,
	}
	providerClient, err := provider.BuildGitProvider(providerCfg)
	if err != nil {
		return err
	}

	applicationRepo, err := repo.CloneApplicationRepo(
		&repo.CloneOptions{
			URL:            addArgs.originUrl,
			Branch:         addArgs.originBranch,
			Username:       addGithubArgs.owner,
			Password:       ghToken,
			PrivateKeyFile: addArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			CaBundle:       caBundle,
		},
		status,
	)
	if err != nil {
		return err
	}
	head, err := applicationRepo.Git().Head()
	if err != nil {
		return err
	}

	clusterRepo, err := repo.CloneClusterRepo(
		&repo.CloneOptions{
			RepositoryName: addGithubArgs.fleet,
			Owner:          addGithubArgs.owner,
			Branch:         addArgs.fleetBranch,
			Username:       addGithubArgs.owner,
			Password:       ghToken,
			PrivateKeyFile: addArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			Personal:       addGithubArgs.personal,
			Reconcile:      addGithubArgs.reconcile,
			Teams:          mapTeamSlice(addGithubArgs.teams, github.DefaultPermission),
			// CaBundle:       caBundle,
			// SshHostname:    addArgs.sshHostname,
			Provider: providerClient,
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
	err = applicationRepo.RenderApplicationConfig(
		addArgs.values,
		clusterRepo.Config(),
		&repo.CloneOptions{
			Username:       addGithubArgs.owner,
			Password:       ghToken,
			PrivateKeyFile: addArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			Personal:       addGithubArgs.personal,
			Reconcile:      addGithubArgs.reconcile,
			Teams:          mapTeamSlice(addGithubArgs.teams, github.DefaultPermission),
			CaBundle:       caBundle,
			SshHostname:    addArgs.sshHostname,
			Provider:       providerClient,
		},
		status,
	)
	if err != nil {
		return err
	}
	if addArgs.applicationName != "" {
		applicationRepo.Config().Name = addArgs.applicationName
	}
	if addArgs.applicationNamespace != "" {
		applicationRepo.Config().Namespace = addArgs.applicationNamespace
	}
	originUrl, transportType, err := repo.UniversalURL(addArgs.originUrl)
	if err != nil {
		return err
	}
	applicationRepo.Config().Repository = originUrl
	applicationRepo.Config().TransportType = transportType
	applicationRepo.Config().Sha = head
	alreadyInstalled := false
	err = applicationRepo.Config().Check(clusterRepo.Config(), alreadyInstalled, status)
	if err != nil {
		return err
	}
	err = applicationRepo.Render(repo.Repository{
		Owner:  addGithubArgs.owner,
		Name:   addGithubArgs.destination,
		Branch: addArgs.destinationBranch,
	}, addGithubArgs.owner, ghToken, status)
	if err != nil {
		return err
	}
	err = applicationRepo.Encrypt(clusterRepo.Config(), status)
	if err != nil {
		return err
	}
	transportType = "ssh"
	if addArgs.tokenAuth == true {
		transportType = "https"
	}
	destinationUrl, repository, err := repo.Create(&repo.CreateOptions{
		RepositoryName: addGithubArgs.destination,
		Owner:          addGithubArgs.owner,
		TransportType:  transportType,
		Branch:         addArgs.destinationBranch,
		Timeout:        rootArgs.timeout,
		Personal:       addGithubArgs.personal,
		Reconcile:      addGithubArgs.reconcile,
		Teams:          mapTeamSlice(addGithubArgs.teams, github.DefaultPermission),
		SshHostname:    addArgs.sshHostname,
		Provider:       providerClient,
	}, status)
	if err != nil {
		return err
	}
	applicationRepo.Git().SetAuth(addGithubArgs.owner, ghToken)
	err = applicationRepo.CommitPush(
		addArgs.authorName,
		addArgs.authorEmail,
		"[add application] Create application repository for "+applicationRepo.Config().Name,
		destinationUrl,
		addArgs.destinationBranch,
		rootArgs.timeout,
		status,
	)
	if err != nil {
		return err
	}
	publicKey, err := clusterRepo.AddApplication(
		destinationUrl,
		addArgs.destinationBranch,
		"github",
		addArgs.destinationPrivate,
		applicationRepo.Config(),
		addArgs.clusterRole,
		addArgs.decryptionSecret,
		addArgs.path,
		&yaml.SourceSecretOptions{
			Namespace:      applicationRepo.Config().Namespace,
			Name:           addArgs.sourceSecretName,
			Username:       "git",
			Password:       ghToken,
			TokenAuth:      addArgs.tokenAuth,
			CaFile:         addArgs.caFile,
			KeyAlgorithm:   addArgs.keyAlgorithm,
			KeyRSABits:     addArgs.keyRSABits,
			KeyECDSACurve:  addArgs.keyECDSACurve,
			Hostname:       addGithubArgs.hostname,
			SshHostname:    addArgs.sshHostname,
			PrivateKeyFile: addArgs.privateKeyFile,
			PlainProvider:  false,
		},
		status,
	)
	if err != nil {
		return err
	}
	if addArgs.destinationPrivate == true {
		ctx, cancel := context.WithTimeout(context.Background(), rootArgs.timeout)
		defer cancel()
		err = reconcileDeployKey(ctx, publicKey, repository)
		if err != nil {
			return err
		}
	}
	err = clusterRepo.CommitPush(
		addArgs.authorName,
		addArgs.authorEmail,
		"[add application] Add "+applicationRepo.Config().Name+" to the cluster",
		"",
		addArgs.fleetBranch,
		rootArgs.timeout,
		status,
	)
	if err != nil {
		return err
	}
	return nil
}
