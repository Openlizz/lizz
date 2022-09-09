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
	"strings"

	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"gitlab.com/openlizz/lizz/internal/repo"
	"gitlab.com/openlizz/lizz/internal/yaml"
)

var addGitCmd = &cobra.Command{
	Use:   "git",
	Short: "Add an application from and to any Git server",
	Long: `The add git command is used to add a Lizz compatible application to the cluster when the 
	repositories are stored in a Git server. It updates the fleet git repository with the new application 
	and	creates a git repository for the new application.`,
	RunE: addGitCmdRun,
}

type addGitFlags struct {
	destinationUrl string
	fleetUrl       string
	username       string
	password       string
	silent         bool
}

var addGitArgs addGitFlags

func init() {
	addGitCmd.Flags().StringVar(&addGitArgs.destinationUrl, "destination-url", "", "Git repository URL where to push the application repository")
	addGitCmd.Flags().StringVar(&addGitArgs.fleetUrl, "fleet-url", "", "Git repository URL of the fleet repository")
	addGitCmd.Flags().StringVarP(&addGitArgs.username, "username", "u", "git", "basic authentication username")
	addGitCmd.Flags().StringVarP(&addGitArgs.password, "password", "p", "", "basic authentication password")
	addGitCmd.Flags().BoolVarP(&addGitArgs.silent, "silent", "s", false, "assumes the deploy key is already setup, skips confirmation")

	addCmd.AddCommand(addGitCmd)
}

func addGitCmdRun(cmd *cobra.Command, args []string) error {
	logger.V(0).Infof("Add new application...")

	var caBundle []byte
	if addArgs.caFile != "" {
		var err error
		caBundle, err = os.ReadFile(addArgs.caFile)
		if err != nil {
			return fmt.Errorf("unable to read TLS CA file: %w", err)
		}
	}

	applicationRepo, err := repo.CloneApplicationRepo(
		&repo.CloneOptions{
			URL:            addArgs.originUrl,
			Branch:         addArgs.originBranch,
			Username:       addGitArgs.username,
			Password:       addGitArgs.password,
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
			URL:            addGitArgs.fleetUrl,
			Branch:         addArgs.fleetBranch,
			Username:       addGitArgs.username,
			Password:       addGitArgs.password,
			PrivateKeyFile: addArgs.privateKeyFile,
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
	err = applicationRepo.RenderApplicationConfig(
		addArgs.values,
		clusterRepo.Config(),
		&repo.CloneOptions{
			Username:       addGitArgs.username,
			Password:       addGitArgs.password,
			PrivateKeyFile: addArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			CaBundle:       caBundle,
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
		URL:    addGitArgs.destinationUrl,
		Branch: addArgs.destinationBranch,
	}, addGitArgs.username, addGitArgs.password, status)
	if err != nil {
		return err
	}
	err = applicationRepo.Encrypt(clusterRepo.Config(), status)
	if err != nil {
		return err
	}
	err = applicationRepo.CommitPush(
		addArgs.authorName,
		addArgs.authorEmail,
		"[add application] Create application repository for "+applicationRepo.Config().Name,
		addGitArgs.destinationUrl,
		addArgs.destinationBranch,
		rootArgs.timeout,
		status,
	)
	if err != nil {
		return err
	}
	publicKey, err := clusterRepo.AddApplication(
		addGitArgs.destinationUrl,
		addArgs.destinationBranch,
		"git",
		addArgs.destinationPrivate,
		applicationRepo.Config(),
		addArgs.clusterRole,
		addArgs.decryptionSecret,
		addArgs.path,
		&yaml.SourceSecretOptions{
			Namespace:      applicationRepo.Config().Namespace,
			Name:           addArgs.sourceSecretName,
			Username:       addGitArgs.username,
			Password:       addGitArgs.password,
			TokenAuth:      addArgs.tokenAuth,
			CaFile:         addArgs.caFile,
			KeyAlgorithm:   addArgs.keyAlgorithm,
			KeyRSABits:     addArgs.keyRSABits,
			KeyECDSACurve:  addArgs.keyECDSACurve,
			SshHostname:    addArgs.sshHostname,
			PrivateKeyFile: addArgs.privateKeyFile,
			PlainProvider:  true,
		},
		status,
	)
	if err != nil {
		return err
	}
	if addArgs.destinationPrivate == true {
		ctx, cancel := context.WithTimeout(context.Background(), rootArgs.timeout)
		defer cancel()
		err = promptPublicKey(ctx, publicKey)
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

func promptPublicKey(ctx context.Context, publicKey string) error {
	logger.V(0).Infof(" • public key: %s", strings.TrimSpace(publicKey))
	if !addGitArgs.silent {
		prompt := promptui.Prompt{
			Label:     "Please give the key access to your repository",
			IsConfirm: true,
		}
		_, err := prompt.Run()
		if err != nil {
			return fmt.Errorf("aborting")
		}
	}
	return nil
}
