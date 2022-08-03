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
)

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "",
	Long:  ``,
}

type envFlags struct {
	name        string
	value       string
	fleetBranch string

	authorName  string
	authorEmail string
}

var envArgs envFlags

func init() {
	envCmd.PersistentFlags().StringVar(&envArgs.name, "name", "", "name of the env variable to add")
	envCmd.PersistentFlags().StringVar(&envArgs.value, "value", "", "value of the env variable to add")
	envCmd.PersistentFlags().StringVar(&envArgs.fleetBranch, "fleet-branch", "main", "Git branch of the fleet repository")

	envCmd.PersistentFlags().StringVar(&envArgs.authorName, "author-name", "Lizz", "author name for Git commits")
	envCmd.PersistentFlags().StringVar(&envArgs.authorEmail, "author-email", "", "author email for Git commits")

	rootCmd.AddCommand(envCmd)
}
