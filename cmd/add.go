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
	"time"

	"github.com/spf13/cobra"
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
	originUrl        string
	originBranch     string
	clusterRole      bool
	decryptionSecret string
	path             string
	destinationUrl   string
	fleetUrl         string
	fleetBranch      string
	interval         time.Duration
	username         string
	password         string
	silent           bool

	authorName  string
	authorEmail string
}

var addArgs addFlags

func init() {
	addCmd.Flags().StringVar(&addArgs.originUrl, "originUrl", "", "Git repository URL where the application is located")
	addCmd.Flags().StringVar(&addArgs.originBranch, "originBranch", "main", "Git branch of the application origin repository")
	addCmd.Flags().BoolVar(&addArgs.clusterRole, "clusterRole", false, "assumes the deploy key is already setup, skips confirmation")
	addCmd.Flags().StringVar(&addArgs.decryptionSecret, "decryptionSecret", "sops-age", "name of the secret containing the AGE secret key")
	addCmd.Flags().StringVar(&addArgs.path, "path", "./default", "path to kustomization in the application repository")
	addCmd.Flags().StringVar(&addArgs.destinationUrl, "destinationUrl", "", "Git repository URL where to push the application repository")
	addCmd.Flags().StringVar(&addArgs.fleetUrl, "fleetUrl", "", "Git repository URL of the fleet repository")
	addCmd.Flags().StringVar(&addArgs.fleetBranch, "fleetBranch", "main", "Git branch of the fleet repository")
	addCmd.Flags().DurationVar(&addArgs.interval, "interval", time.Minute, "sync interval")
	addCmd.Flags().StringVarP(&addArgs.username, "username", "u", "git", "basic authentication username")
	addCmd.Flags().StringVarP(&addArgs.password, "password", "p", "", "basic authentication password")
	addCmd.Flags().BoolVarP(&addArgs.silent, "silent", "s", false, "assumes the deploy key is already setup, skips confirmation")

	addCmd.Flags().StringVar(&addArgs.authorName, "author-name", "Lizz", "author name for Git commits")
	addCmd.Flags().StringVar(&addArgs.authorEmail, "author-email", "", "author email for Git commits")

	rootCmd.AddCommand(addCmd)
}

func addCmdRun(cmd *cobra.Command, args []string) error {
	logger.Actionf("Clone application repo.")
	applicationRepo, err := repo.CloneApplicationRepo(addArgs.originUrl, addArgs.originBranch, addArgs.username, addArgs.password, rootArgs.timeout)
	if err != nil {
		return err
	}
	head, err := applicationRepo.Git().Head()
	if err != nil {
		return err
	}
	logger.Actionf("Clone cluster repo.")
	clusterRepo, err := repo.CloneClusterRepo(addArgs.fleetUrl, addArgs.fleetBranch, addArgs.username, addArgs.password, rootArgs.timeout)
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
	applicationRepo.Config().Repository = addArgs.originUrl
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
	logger.Actionf("Commit and push application repo.")
	err = applicationRepo.CommitPush(addArgs.authorName, addArgs.authorEmail, "[add application] Create application repository for "+applicationRepo.Config().Name, addArgs.destinationUrl, rootArgs.timeout)
	if err != nil {
		return err
	}
	logger.Actionf("Add application to the cluster repo.")
	err = clusterRepo.AddApplication(addArgs.destinationUrl, applicationRepo.Config(), addArgs.clusterRole, addArgs.destinationUrl, addArgs.decryptionSecret, addArgs.path)
	if err != nil {
		return err
	}
	logger.Actionf("Commit and push cluster repo.")
	err = clusterRepo.CommitPush(addArgs.authorName, addArgs.authorEmail, "[add application] Add "+applicationRepo.Config().Name+" to the cluster", "", rootArgs.timeout)
	if err != nil {
		return err
	}
	return nil
}
