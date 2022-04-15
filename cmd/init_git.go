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

var initGitCmd = &cobra.Command{
	Use:   "git",
	Short: "",
	Long:  ``,
	RunE:  initGitCmdRun,
}

type initGitFlags struct {
	destinationUrl string
	username       string
	password       string
	privateKeyFile string
}

var initGitArgs initGitFlags

func init() {
	initGitCmd.Flags().StringVar(&initGitArgs.destinationUrl, "destination-url", "", "Git repository URL")
	initGitCmd.Flags().StringVarP(&initGitArgs.username, "username", "u", "git", "basic authentication username")
	initGitCmd.Flags().StringVarP(&initGitArgs.password, "password", "p", "", "basic authentication password")
	initGitCmd.Flags().StringVar(&initGitArgs.privateKeyFile, "private-key-file", "", "path to a private key file used for authenticating to the Git SSH server")

	initCmd.AddCommand(initGitCmd)
}

func initGitCmdRun(cmd *cobra.Command, args []string) error {
	logger.V(0).Infof("Initialize the cluster repository...")

	clusterRepo, err := repo.CloneClusterRepo(
		&repo.CloneOptions{
			URL:            initArgs.originUrl,
			Branch:         initArgs.originBranch,
			Username:       initGitArgs.username,
			Password:       initGitArgs.password,
			PrivateKeyFile: initGitArgs.privateKeyFile,
			Timeout:        rootArgs.timeout,
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
	originUrl, err := config.UniversalURL(initArgs.originUrl)
	if err != nil {
		return err
	}
	err = clusterRepo.NewClusterConfig(originUrl, head, status)
	if err != nil {
		return err
	}
	clusterRepo.CommitPush(
		initArgs.authorName,
		initArgs.authorEmail,
		"Initialize cluster repository",
		initGitArgs.destinationUrl,
		rootArgs.timeout,
		status,
	)
	if err != nil {
		return err
	}
	return nil
}
