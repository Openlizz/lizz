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
	"os"
	"path/filepath"
	"time"

	// gogitv5 "github.com/go-git/go-git/v5"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
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
	interval       time.Duration
	username       string
	password       string
	silent         bool

	authorName  string
	authorEmail string
}

var initArgs initFlags

func init() {
	initCmd.Flags().StringVar(&initArgs.originUrl, "originUrl", "", "Git repository URL")
	initCmd.Flags().StringVar(&initArgs.originBranch, "originBranch", "main", "Git branch of the repository")
	initCmd.Flags().StringVar(&initArgs.destinationUrl, "destinationUrl", "", "Git repository URL")
	initCmd.Flags().DurationVar(&initArgs.interval, "interval", time.Minute, "sync interval")
	initCmd.Flags().StringVarP(&initArgs.username, "username", "u", "git", "basic authentication username")
	initCmd.Flags().StringVarP(&initArgs.password, "password", "p", "", "basic authentication password")
	initCmd.Flags().BoolVarP(&initArgs.silent, "silent", "s", false, "assumes the deploy key is already setup, skips confirmation")

	initCmd.Flags().StringVar(&initArgs.authorName, "author-name", "Lizz", "author name for Git commits")
	initCmd.Flags().StringVar(&initArgs.authorEmail, "author-email", "", "author email for Git commits")

	rootCmd.AddCommand(initCmd)
}

func initCmdRun(cmd *cobra.Command, args []string) error {

	/////////////////////////////
	// Create Fleet repository //
	/////////////////////////////

	gitClient, tmpDir, err := cloneRepositoryTemp(initArgs.originUrl, initArgs.originBranch, initArgs.username, initArgs.password, rootArgs.timeout)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	head, err := gitClient.Head()
	if err != nil {
		return err
	}
	clusterConfig := ClusterConfig{
		Repository:     initArgs.originUrl,
		Sha:            head,
		Applications:   []Application{},
		Configurations: []Configuration{},
	}
	clusterConfigYaml, err := yaml.Marshal(&clusterConfig)
	if err != nil {
		return err
	}
	logger.Actionf("creating cluster config file")
	f, err := os.Create(filepath.Join(tmpDir, "config.yaml"))
	if err != nil {
		return err
	}
	l, err := f.WriteString(string(clusterConfigYaml))
	if err != nil {
		f.Close()
		return err
	}
	if l > 0 {
		logger.Successf("created file")
	}
	err = f.Close()
	if err != nil {
		return err
	}
	logger.Actionf("committing and pushing fleet configuration file")
	err = commitAndpush(gitClient, initArgs.authorName, initArgs.authorEmail, "Initialize fleet repository", initArgs.originBranch, initArgs.destinationUrl, rootArgs.timeout)
	if err != nil {
		return err
	}

	return nil
}
