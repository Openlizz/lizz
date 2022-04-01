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
	"log"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var VERSION = "0.0.0-dev.0"

var rootCmd = &cobra.Command{
	Use:           "lizz",
	Version:       VERSION,
	SilenceUsage:  true,
	SilenceErrors: true,
	Short:         "",
	Long:          ``,
}

var logger = stderrLogger{stderr: os.Stderr}

type rootFlags struct {
	timeout time.Duration
	verbose bool
}

var rootArgs rootFlags

func Execute() {
	log.SetFlags(0)
	err := rootCmd.Execute()
	if err != nil {
		logger.Failuref("%v", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().
		DurationVar(&rootArgs.timeout, "timeout", 5*time.Minute, "timeout for this operation")
	rootCmd.PersistentFlags().
		BoolVar(&rootArgs.verbose, "verbose", false, "print generated objects")
	rootCmd.SetOut(os.Stdout)
}
