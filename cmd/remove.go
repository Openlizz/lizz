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
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	kustomizePatch "sigs.k8s.io/kustomize/pkg/patch"
	kustomize "sigs.k8s.io/kustomize/pkg/types"
	"sigs.k8s.io/yaml"
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

	gitClientFleet, tmpDirFleet, err := cloneRepositoryTemp(removeArgs.fleetUrl, removeArgs.fleetBranch, removeArgs.username, removeArgs.password, rootArgs.timeout)
	if err != nil {
		return err
	}
	// defer os.RemoveAll(tmpDirFleet)
	var clusterConfig *ClusterConfig
	if _, err := os.Stat(filepath.Join(tmpDirFleet, "config.yaml")); err == nil {
		logger.Actionf("updating cluster config file")
		data, err := os.ReadFile(filepath.Join(tmpDirFleet, "config.yaml"))
		if err != nil {
			return err
		}
		clusterConfig = &ClusterConfig{}
		err = yaml.Unmarshal([]byte(data), &clusterConfig)
		if err != nil {
			return err
		}
	} else {
		return err
	}
	clusterConfig.Applications = removeApplicationByName(clusterConfig.Applications, removeArgs.applicationName)
	clusterConfigYaml, err := yaml.Marshal(clusterConfig)
	if err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(tmpDirFleet, "config.yaml"))
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
	logger.Actionf("committing and pushing cluster configuration file")
	err = commitAndpush(gitClientFleet, removeArgs.authorName, removeArgs.authorEmail, "Update cluster configuration file", removeArgs.fleetBranch, "", rootArgs.timeout)
	if err != nil {
		return err
	}
	pathToApplications := filepath.Join(tmpDirFleet, "applications")
	pathToApplicationsBase := filepath.Join(pathToApplications, "base")
	pathToApplicationsBaseApplication := filepath.Join(pathToApplicationsBase, removeArgs.applicationName)
	if _, err := os.Stat(pathToApplicationsBaseApplication); err == nil {
		err = os.RemoveAll(pathToApplicationsBaseApplication)
		if err != nil {
			return err
		}
	} else if errors.Is(err, os.ErrNotExist) {
		logger.Warningf("impossible to remove %s", pathToApplicationsBaseApplication)

	} else {
		return err

	}
	if _, err := os.Stat(filepath.Join(pathToApplications, removeArgs.applicationName+"-patch.yaml")); err == nil {
		err = os.RemoveAll(filepath.Join(pathToApplications, removeArgs.applicationName+"-patch.yaml"))
		if err != nil {
			return err
		}
	} else if errors.Is(err, os.ErrNotExist) {
		logger.Warningf("impossible to remove %s", filepath.Join(pathToApplications, removeArgs.applicationName+"-patch.yaml"))

	} else {
		return err

	}
	var applications kustomize.Kustomization
	if _, err := os.Stat(filepath.Join(pathToApplications, "kustomization.yaml")); errors.Is(err, os.ErrNotExist) {
		applications = kustomize.Kustomization{
			Resources:             []string{},
			PatchesStrategicMerge: []kustomizePatch.StrategicMerge{},
		}

	} else {
		data, err := os.ReadFile(filepath.Join(pathToApplications, "kustomization.yaml"))
		if err != nil {
			return err
		}
		applicationsPtr := &kustomize.Kustomization{}
		err = yaml.Unmarshal([]byte(data), &applicationsPtr)
		if err != nil {
			return err
		}
		applications = *applicationsPtr
		applications.Resources = removeString(applications.Resources, "./base/"+removeArgs.applicationName)
		applications.PatchesStrategicMerge = removeStrategicMerge(applications.PatchesStrategicMerge, removeArgs.applicationName+"-patch.yaml")
	}
	applicationsString, err := exportKustomization(applications)
	if err != nil {
		return err
	}
	f, err = os.Create(filepath.Join(pathToApplications, "kustomization.yaml"))
	if err != nil {
		return err
	}
	l, err = f.WriteString(applicationsString)
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
	logger.Actionf("committing and pushing application files to fleet repository")
	err = commitAndpush(gitClientFleet, removeArgs.authorName, removeArgs.authorEmail, "Update cluster configuration file", removeArgs.fleetBranch, "", rootArgs.timeout)
	if err != nil {
		return err
	}
	return nil
}
