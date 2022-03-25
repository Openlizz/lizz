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

var removeCmd = &cobra.Command{
	Use:   "remove",
	Short: "",
	Long:  ``,
	RunE:  removeCmdRun,
}

type removeFlags struct {
	applicationName string
	originUrl       string
	originBranch    string
	clusterRole     bool
	path            string
	destinationUrl  string
	fleetUrl        string
	fleetBranch     string
	interval        time.Duration
	username        string
	password        string
	silent          bool

	authorName  string
	authorEmail string
}

var removeArgs removeFlags

func init() {
	removeCmd.Flags().StringVar(&removeArgs.applicationName, "applicationName", "", "Name of the application to remove")
	removeCmd.Flags().StringVar(&removeArgs.fleetUrl, "fleetUrl", "", "Git repository URL of the fleet repository")
	removeCmd.Flags().StringVar(&removeArgs.fleetBranch, "fleetBranch", "main", "Git branch of the fleet repository")
	removeCmd.Flags().DurationVar(&removeArgs.interval, "interval", time.Minute, "sync interval")
	removeCmd.Flags().StringVarP(&removeArgs.username, "username", "u", "git", "basic authentication username")
	removeCmd.Flags().StringVarP(&removeArgs.password, "password", "p", "", "basic authentication password")
	removeCmd.Flags().BoolVarP(&removeArgs.silent, "silent", "s", false, "assumes the deploy key is already setup, skips confirmation")

	removeCmd.Flags().StringVar(&removeArgs.authorName, "author-name", "Lizz", "author name for Git commits")
	removeCmd.Flags().StringVar(&removeArgs.authorEmail, "author-email", "", "author email for Git commits")

	rootCmd.AddCommand(removeCmd)
}

func removeCmdRun(cmd *cobra.Command, args []string) error {
	clusterRepo, err := repo.CloneClusterRepo(addArgs.fleetUrl, addArgs.fleetBranch, addArgs.username, addArgs.password, rootArgs.timeout)
	if err != nil {
		return err
	}
	err = clusterRepo.OpenClusterConfig()
	if err != nil {
		return err
	}
	err = clusterRepo.RemoveApplication(clusterRepo.Config().Repository, removeArgs.applicationName)
	if err != nil {
		return err
	}
	err = clusterRepo.CommitPush(addArgs.authorName, addArgs.authorEmail, "[remove application] Remove "+removeArgs.applicationName+" from the cluster", "", rootArgs.timeout)
	if err != nil {
		return err
	}
	return nil
	return nil
}
