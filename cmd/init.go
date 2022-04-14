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
	"github.com/spf13/cobra"
	"gitlab.com/openlizz/lizz/internal/config"
	"gitlab.com/openlizz/lizz/internal/repo"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "",
	Long:  ``,
	RunE:  initCmdRun,
}

type initFlags struct {
	originUrl      string
	originBranch   string
	destinationUrl string
	username       string
	password       string
	privateKeyFile string

	authorName  string
	authorEmail string
}

var initArgs initFlags

func init() {
	initCmd.Flags().StringVar(&initArgs.originUrl, "origin-url", "", "Git repository URL")
	initCmd.Flags().StringVar(&initArgs.originBranch, "origin-branch", "main", "Git branch of the repository")
	initCmd.Flags().StringVar(&initArgs.destinationUrl, "destination-url", "", "Git repository URL")
	initCmd.Flags().StringVarP(&initArgs.username, "username", "u", "git", "basic authentication username")
	initCmd.Flags().StringVarP(&initArgs.password, "password", "p", "", "basic authentication password")
	initCmd.Flags().StringVar(&initArgs.privateKeyFile, "private-key-file", "", "path to a private key file used for authenticating to the Git SSH server")

	initCmd.Flags().StringVar(&initArgs.authorName, "author-name", "Lizz", "author name for Git commits")
	initCmd.Flags().StringVar(&initArgs.authorEmail, "author-email", "", "author email for Git commits")

	rootCmd.AddCommand(initCmd)
}

func initCmdRun(cmd *cobra.Command, args []string) error {
	clusterRepo, err := repo.CloneClusterRepo(
		initArgs.originUrl,
		initArgs.originBranch,
		initArgs.username,
		initArgs.password,
		initArgs.privateKeyFile,
		rootArgs.timeout,
	)
	if err != nil {
		return err
	}
	head, err := clusterRepo.Git().Head()
	if err != nil {
		return err
	}
	originUrl, err := config.UniversalURL(initArgs.originUrl)
	if err != nil {
		return err
	}
	clusterRepo.NewClusterConfig(originUrl, head)
	clusterRepo.CommitPush(
		initArgs.authorName,
		initArgs.authorEmail,
		"Initialize cluster repository",
		initArgs.destinationUrl,
		rootArgs.timeout,
	)
	if err != nil {
		return err
	}
	return nil
}
