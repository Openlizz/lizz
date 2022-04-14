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
	"strings"
	"time"

	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"gitlab.com/openlizz/lizz/internal/config"
	"gitlab.com/openlizz/lizz/internal/flags"
	"gitlab.com/openlizz/lizz/internal/repo"
)

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "",
	Long:  ``,
	RunE:  addCmdRun,
}

const (
	tenantLabel = "toolkit.fluxcd.io/tenant"
)

type addFlags struct {
	originUrl          string
	originBranch       string
	clusterRole        bool
	decryptionSecret   string
	path               string
	destinationUrl     string
	destinationPrivate bool
	fleetUrl           string
	fleetBranch        string
	interval           time.Duration
	sourceSecretName   string
	username           string
	password           string
	tokenAuth          bool
	keyAlgorithm       flags.PublicKeyAlgorithm
	keyRSABits         flags.RSAKeyBits
	keyECDSACurve      flags.ECDSACurve
	sshHostname        string
	caFile             string
	privateKeyFile     string
	silent             bool

	authorName  string
	authorEmail string
}

var addArgs addFlags

func init() {
	addCmd.Flags().StringVar(&addArgs.originUrl, "origin-url", "", "Git repository URL where the application is located")
	addCmd.Flags().StringVar(&addArgs.originBranch, "origin-branch", "main", "Git branch of the application origin repository")
	addCmd.Flags().BoolVar(&addArgs.clusterRole, "cluster-role", false, "assumes the deploy key is already setup, skips confirmation")
	addCmd.Flags().StringVar(&addArgs.decryptionSecret, "decryption-secret", "sops-age", "name of the secret containing the AGE secret key")
	addCmd.Flags().StringVar(&addArgs.path, "path", "./default", "path to kustomization in the application repository")
	addCmd.Flags().StringVar(&addArgs.destinationUrl, "destination-url", "", "Git repository URL where to push the application repository")
	addCmd.Flags().BoolVar(&addArgs.destinationPrivate, "private", true, "if true, the repository is setup or configured as private")
	addCmd.Flags().StringVar(&addArgs.fleetUrl, "fleet-url", "", "Git repository URL of the fleet repository")
	addCmd.Flags().StringVar(&addArgs.fleetBranch, "fleet-branch", "main", "Git branch of the fleet repository")
	addCmd.Flags().DurationVar(&addArgs.interval, "interval", time.Minute, "sync interval")
	addCmd.Flags().StringVar(&addArgs.sourceSecretName, "sourcesecret-name", "sourcesecret", "Name of the source secret containing the credentials for the desctionation repository")
	addCmd.Flags().StringVarP(&addArgs.username, "username", "u", "git", "basic authentication username")
	addCmd.Flags().StringVarP(&addArgs.password, "password", "p", "", "basic authentication password")
	addCmd.Flags().StringVar(&addArgs.privateKeyFile, "private-key-file", "", "path to a private key file used for authenticating to the Git SSH server")
	addCmd.Flags().BoolVar(&addArgs.tokenAuth, "token-auth", false, "when enabled, the personal access token will be used instead of SSH deploy key")
	addCmd.Flags().Var(&addArgs.keyAlgorithm, "ssh-key-algorithm", addArgs.keyAlgorithm.Description())
	addCmd.Flags().Var(&addArgs.keyRSABits, "ssh-rsa-bits", addArgs.keyRSABits.Description())
	addCmd.Flags().Var(&addArgs.keyECDSACurve, "ssh-ecdsa-curve", addArgs.keyECDSACurve.Description())
	addCmd.Flags().StringVar(&addArgs.sshHostname, "ssh-hostname", "", "SSH hostname, to be used when the SSH host differs from the HTTPS one")
	addCmd.Flags().StringVar(&addArgs.caFile, "ca-file", "", "path to TLS CA file used for validating self-signed certificates")
	addCmd.Flags().BoolVarP(&addArgs.silent, "silent", "s", false, "assumes the deploy key is already setup, skips confirmation")

	addCmd.Flags().StringVar(&addArgs.authorName, "author-name", "Lizz", "author name for Git commits")
	addCmd.Flags().StringVar(&addArgs.authorEmail, "author-email", "", "author email for Git commits")

	rootCmd.AddCommand(addCmd)
}

func addCmdRun(cmd *cobra.Command, args []string) error {
	logger.Actionf("Clone application repository.")
	applicationRepo, err := repo.CloneApplicationRepo(
		addArgs.originUrl,
		addArgs.originBranch,
		addArgs.username,
		addArgs.password,
		addArgs.privateKeyFile,
		rootArgs.timeout,
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
		addArgs.fleetUrl,
		addArgs.fleetBranch,
		addArgs.username,
		addArgs.password,
		"",
		rootArgs.timeout,
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
	originUrl, err := config.UniversalURL(addArgs.originUrl)
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
	// > create the repository if does not exists
	err = applicationRepo.CommitPush(
		addArgs.authorName,
		addArgs.authorEmail,
		"[add application] Create application repository for "+applicationRepo.Config().Name,
		addArgs.destinationUrl,
		rootArgs.timeout,
	)
	if err != nil {
		return err
	}
	logger.Actionf("Add application to the cluster repository.")
	// > use gitlab_token as sourcesecret if private
	publicKey, err := clusterRepo.AddApplication(
		addArgs.destinationUrl,
		addArgs.destinationPrivate,
		applicationRepo.Config(),
		addArgs.clusterRole,
		addArgs.destinationUrl,
		addArgs.decryptionSecret,
		addArgs.path,
		addArgs.sourceSecretName,
		addArgs.username,
		addArgs.password,
		addArgs.tokenAuth,
		addArgs.caFile,
		addArgs.keyAlgorithm,
		addArgs.keyRSABits,
		addArgs.keyECDSACurve,
		addArgs.sshHostname,
		addArgs.privateKeyFile,
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
	if !addArgs.silent {
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
