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
	"gitlab.com/openlizz/lizz/internal/config"
	"gitlab.com/openlizz/lizz/internal/repo"
	"gitlab.com/openlizz/lizz/internal/yaml"
)

var addGitCmd = &cobra.Command{
	Use:   "git",
	Short: "",
	Long:  ``,
	RunE:  addGitCmdRun,
}

type addGitFlags struct {
	originUrl      string
	destinationUrl string
	fleetUrl       string
	username       string
	password       string
	privateKeyFile string
	silent         bool
}

var addGitArgs addGitFlags

func init() {
	addGitCmd.Flags().StringVar(&addGitArgs.originUrl, "origin-url", "", "Git repository URL where the application is located")
	addGitCmd.Flags().StringVar(&addGitArgs.destinationUrl, "destination-url", "", "Git repository URL where to push the application repository")
	addGitCmd.Flags().StringVar(&addGitArgs.fleetUrl, "fleet-url", "", "Git repository URL of the fleet repository")
	addGitCmd.Flags().StringVarP(&addGitArgs.username, "username", "u", "git", "basic authentication username")
	addGitCmd.Flags().StringVarP(&addGitArgs.password, "password", "p", "", "basic authentication password")
	addGitCmd.Flags().StringVar(&addGitArgs.privateKeyFile, "private-key-file", "", "path to a private key file used for authenticating to the Git SSH server")
	addGitCmd.Flags().BoolVarP(&addGitArgs.silent, "silent", "s", false, "assumes the deploy key is already setup, skips confirmation")

	addCmd.AddCommand(addGitCmd)
}

func addGitCmdRun(cmd *cobra.Command, args []string) error {

	var caBundle []byte
	if addArgs.caFile != "" {
		var err error
		caBundle, err = os.ReadFile(addArgs.caFile)
		if err != nil {
			return fmt.Errorf("unable to read TLS CA file: %w", err)
		}
	}

	logger.Actionf("Clone application repository.")
	applicationRepo, err := repo.CloneApplicationRepo(
		&repo.CloneOptions{
			URL:            addGitArgs.originUrl,
			Branch:         addArgs.originBranch,
			Username:       addGitArgs.username,
			Password:       addGitArgs.password,
			PrivateKeyFile: addGitArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
			CaBundle:       caBundle,
		},
	)
	if err != nil {
		return err
	}
	head, err := applicationRepo.Git().Head()
	if err != nil {
		return err
	}
	logger.Actionf("Clone cluster repository.")
	clusterRepo, err := repo.CloneClusterRepo(
		&repo.CloneOptions{
			URL:            addGitArgs.fleetUrl,
			Branch:         addArgs.fleetBranch,
			Username:       addGitArgs.username,
			Password:       addGitArgs.password,
			PrivateKeyFile: addGitArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
		},
	)
	if err != nil {
		return err
	}
	err = clusterRepo.OpenClusterConfig()
	if err != nil {
		return err
	}
	logger.Actionf("Render application configuration.")
	err = applicationRepo.RenderApplicationConfig(clusterRepo.Config())
	if err != nil {
		return err
	}
	originUrl, err := config.UniversalURL(addGitArgs.originUrl)
	if err != nil {
		return err
	}
	applicationRepo.Config().Repository = originUrl
	applicationRepo.Config().Sha = head
	logger.Actionf("Check that the application can be installed.")
	err = applicationRepo.Config().Check()
	if err != nil {
		return err
	}
	logger.Actionf("Render application values.")
	err = applicationRepo.Render()
	if err != nil {
		return err
	}
	logger.Actionf("Encrypt application files.")
	err = applicationRepo.Encrypt(clusterRepo.Config())
	if err != nil {
		return err
	}
	logger.Actionf("Commit and push application repository.")
	err = applicationRepo.CommitPush(
		addArgs.authorName,
		addArgs.authorEmail,
		"[add application] Create application repository for "+applicationRepo.Config().Name,
		addGitArgs.destinationUrl,
		rootArgs.timeout,
	)
	if err != nil {
		return err
	}
	logger.Actionf("Add application to the cluster repository.")
	publicKey, err := clusterRepo.AddApplication(
		addGitArgs.destinationUrl,
		addArgs.destinationPrivate,
		applicationRepo.Config(),
		addArgs.clusterRole,
		addArgs.decryptionSecret,
		addArgs.path,
		&yaml.SourceSecretOptions{
			Namespace:      applicationRepo.Config().Name,
			Name:           addArgs.sourceSecretName,
			Username:       addGitArgs.username,
			Password:       addGitArgs.password,
			TokenAuth:      addArgs.tokenAuth,
			CaFile:         addArgs.caFile,
			KeyAlgorithm:   addArgs.keyAlgorithm,
			KeyRSABits:     addArgs.keyRSABits,
			KeyECDSACurve:  addArgs.keyECDSACurve,
			SshHostname:    addArgs.sshHostname,
			PrivateKeyFile: addGitArgs.privateKeyFile,
			PlainProvider:  true,
		},
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
	logger.Actionf("Commit and push cluster repository.")
	err = clusterRepo.CommitPush(
		addArgs.authorName,
		addArgs.authorEmail,
		"[add application] Add "+applicationRepo.Config().Name+" to the cluster",
		"",
		rootArgs.timeout,
	)
	if err != nil {
		return err
	}
	return nil
}

func promptPublicKey(ctx context.Context, publicKey string) error {
	logger.Successf("public key: %s", strings.TrimSpace(publicKey))
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
