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
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/fluxcd/go-git-providers/gitprovider"
	"github.com/spf13/cobra"
	"gitlab.com/openlizz/lizz/internal/gitlab"
	"gitlab.com/openlizz/lizz/internal/provider"
	"gitlab.com/openlizz/lizz/internal/repo"
	"gitlab.com/openlizz/lizz/internal/yaml"
)

var addGitlabCmd = &cobra.Command{
	Use:   "gitlab",
	Short: "",
	Long:  ``,
	RunE:  addGitlabCmdRun,
}

type addGitlabFlags struct {
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

var addGitlabArgs addGitlabFlags

func init() {
	addGitlabCmd.Flags().StringVar(&addGitlabArgs.owner, "owner", "", "GitLab user or group name")
	addGitlabCmd.Flags().StringVar(&addGitlabArgs.fleet, "fleet", "", "GitLab repository name of the fleet repository")
	addGitlabCmd.Flags().StringVar(&addGitlabArgs.destination, "destination", "", "GitLab repository name where to push the application repository")
	addGitlabCmd.Flags().StringSliceVar(&addGitlabArgs.teams, "team", []string{}, "GitLab teams to be given maintainer access (also accepts comma-separated values)")
	addGitlabCmd.Flags().BoolVar(&addGitlabArgs.personal, "personal", false, "if true, the owner is assumed to be a GitLab user; otherwise a group")
	addGitlabCmd.Flags().DurationVar(&addGitlabArgs.interval, "interval", time.Minute, "sync interval")
	addGitlabCmd.Flags().StringVar(&addGitlabArgs.hostname, "hostname", gitlab.DefaultDomain, "GitLab hostname")
	addGitlabCmd.Flags().BoolVar(&addGitlabArgs.readWriteKey, "read-write-key", false, "if true, the deploy key is configured with read/write permissions")
	addGitlabCmd.Flags().BoolVar(&addGitlabArgs.reconcile, "reconcile", false, "if true, the configured options are also reconciled if the repository already exists")

	addCmd.AddCommand(addGitlabCmd)
}

func addGitlabCmdRun(cmd *cobra.Command, args []string) error {
	logger.V(0).Infof("Add new application...")

	glToken, err := gitlab.GetToken()
	if err != nil {
		return err
	}

	if projectNameIsValid, err := regexp.MatchString(gitlab.ProjectRegex, addGitlabArgs.fleet); err != nil || !projectNameIsValid {
		if err == nil {
			err = fmt.Errorf(
				"%s is an invalid project name for gitlab.\nIt can contain only letters, digits, emojis, '_', '.', dash, space. It must start with letter, digit, emoji or '_'.",
				addGitlabArgs.fleet,
			)
		}
		return err
	}
	if projectNameIsValid, err := regexp.MatchString(gitlab.ProjectRegex, addGitlabArgs.destination); err != nil || !projectNameIsValid {
		if err == nil {
			err = fmt.Errorf(
				"%s is an invalid project name for gitlab.\nIt can contain only letters, digits, emojis, '_', '.', dash, space. It must start with letter, digit, emoji or '_'.",
				addGitlabArgs.destination,
			)
		}
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

	// Build GitLab provider
	providerCfg := provider.Config{
		Provider: provider.GitProviderGitLab,
		Hostname: addGitlabArgs.hostname,
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

	applicationRepo, err := repo.CloneApplicationRepo(
		&repo.CloneOptions{
			URL:      addArgs.originUrl,
			Branch:   addArgs.originBranch,
			Username: addGitlabArgs.owner,
			Password: glToken,
			Timeout:  rootArgs.timeout,
			CaBundle: caBundle,
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
			RepositoryName: addGitlabArgs.fleet,
			Owner:          addGitlabArgs.owner,
			Branch:         addArgs.fleetBranch,
			Username:       addGitlabArgs.owner,
			Password:       glToken,
			Timeout:        rootArgs.timeout,
			Personal:       addGitlabArgs.personal,
			Reconcile:      addGitlabArgs.reconcile,
			Teams:          mapTeamSlice(addGitlabArgs.teams, gitlab.DefaultPermission),
			CaBundle:       caBundle,
			SshHostname:    addArgs.sshHostname,
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
	err = applicationRepo.RenderApplicationConfig(
		addArgs.values,
		clusterRepo.Config(),
		&repo.CloneOptions{
			Username:    addGitlabArgs.owner,
			Password:    glToken,
			Timeout:     rootArgs.timeout,
			Personal:    addGitlabArgs.personal,
			Reconcile:   addGitlabArgs.reconcile,
			Teams:       mapTeamSlice(addGitlabArgs.teams, gitlab.DefaultPermission),
			CaBundle:    caBundle,
			SshHostname: addArgs.sshHostname,
			Provider:    providerClient,
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
	originUrl, err := repo.UniversalURL(addArgs.originUrl)
	if err != nil {
		return err
	}
	applicationRepo.Config().Repository = originUrl
	applicationRepo.Config().Sha = head
	err = applicationRepo.Config().Check(status)
	if err != nil {
		return err
	}
	err = applicationRepo.Render(&repo.Repository{
		Owner:  addGitlabArgs.owner,
		Name:   addGitlabArgs.destination,
		Branch: addArgs.destinationBranch,
	}, addGitlabArgs.owner, glToken, status)
	if err != nil {
		return err
	}
	err = applicationRepo.Encrypt(clusterRepo.Config(), status)
	if err != nil {
		return err
	}
	transportType := "ssh"
	if addArgs.tokenAuth == true {
		transportType = "https"
	}
	destinationUrl, repository, err := repo.Create(&repo.CreateOptions{
		RepositoryName: addGitlabArgs.destination,
		Owner:          addGitlabArgs.owner,
		TransportType:  transportType,
		Branch:         addArgs.destinationBranch,
		Timeout:        rootArgs.timeout,
		Personal:       addGitlabArgs.personal,
		Reconcile:      addGitlabArgs.reconcile,
		Teams:          mapTeamSlice(addGitlabArgs.teams, gitlab.DefaultPermission),
		SshHostname:    addArgs.sshHostname,
		Provider:       providerClient,
	}, status)
	if err != nil {
		return err
	}
	applicationRepo.Git().SetAuth(addGitlabArgs.owner, glToken)
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
		"gitlab",
		addArgs.destinationPrivate,
		applicationRepo.Config(),
		addArgs.clusterRole,
		addArgs.decryptionSecret,
		addArgs.path,
		&yaml.SourceSecretOptions{
			Namespace:     applicationRepo.Config().Namespace,
			Name:          addArgs.sourceSecretName,
			Username:      "git",
			Password:      glToken,
			TokenAuth:     addArgs.tokenAuth,
			CaFile:        addArgs.caFile,
			KeyAlgorithm:  addArgs.keyAlgorithm,
			KeyRSABits:    addArgs.keyRSABits,
			KeyECDSACurve: addArgs.keyECDSACurve,
			Hostname:      addGitlabArgs.hostname,
			SshHostname:   addArgs.sshHostname,
			PlainProvider: false,
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

func reconcileDeployKey(ctx context.Context, publicKey string, repository gitprovider.UserRepository) error {
	if repository == nil {
		return errors.New("repository is required")
	}
	logger.V(0).Infof("public key: %s", strings.TrimSpace(publicKey))

	name := deployKeyName(addArgs.sourceSecretName, addArgs.destinationBranch, addGitlabArgs.destination)
	deployKeyInfo := newDeployKeyInfo(name, publicKey, addGitlabArgs.readWriteKey)

	_, changed, err := repository.DeployKeys().Reconcile(ctx, deployKeyInfo)
	if err != nil {
		return err
	}
	if changed {
		logger.V(0).Infof("configured deploy key %q for %q", deployKeyInfo.Name, repository.Repository().String())
	}
	return nil
}

// newDeployKeyInfo constructs a gitprovider.DeployKeyInfo with the
// given values and returns the result.
func newDeployKeyInfo(name, publicKey string, readWrite bool) gitprovider.DeployKeyInfo {
	keyInfo := gitprovider.DeployKeyInfo{
		Name: name,
		Key:  []byte(publicKey),
	}
	if readWrite {
		keyInfo.ReadOnly = gitprovider.BoolVar(false)
	}
	return keyInfo
}

func deployKeyName(secretName, branch, path string) string {
	var name string
	for _, v := range []string{secretName, branch, path} {
		if v == "" {
			continue
		}
		if name == "" {
			name = v
		} else {
			name = name + "-" + v
		}
	}
	return name
}
