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
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gitlab.com/openlizz/lizz/internal/flags"
	"helm.sh/helm/v3/pkg/strvals"
)

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "",
	Long:  ``,
}

const (
	tenantLabel = "toolkit.fluxcd.io/tenant"
)

type addFlags struct {
	applicationName      string
	applicationNamespace string
	originUrl            string
	originBranch         string
	clusterRole          bool
	decryptionSecret     string
	path                 string
	destinationBranch    string
	destinationPrivate   bool
	fleetBranch          string
	values               []string
	interval             time.Duration
	sourceSecretName     string
	tokenAuth            bool
	keyAlgorithm         flags.PublicKeyAlgorithm
	keyRSABits           flags.RSAKeyBits
	keyECDSACurve        flags.ECDSACurve
	sshHostname          string
	caFile               string
	privateKeyFile       string

	authorName  string
	authorEmail string
}

var addArgs addFlags

func init() {
	addCmd.PersistentFlags().StringVar(&addArgs.applicationName, "name", "", "name of the application to add (default to the name of the application)")
	addCmd.PersistentFlags().StringVar(&addArgs.applicationNamespace, "namespace", "", "namespace where to add the application (default to the name of the application)")
	addCmd.PersistentFlags().StringVar(&addArgs.originUrl, "origin-url", "", "Git repository URL where the application is located")
	addCmd.PersistentFlags().StringVar(&addArgs.originBranch, "origin-branch", "main", "Git branch of the application origin repository")
	addCmd.PersistentFlags().BoolVar(&addArgs.clusterRole, "cluster-role", false, "if true, the service account used has permissions for the all cluster")
	addCmd.PersistentFlags().StringVar(&addArgs.decryptionSecret, "decryption-secret", "sops-age", "name of the secret containing the AGE secret key")
	addCmd.PersistentFlags().StringVar(&addArgs.path, "path", "./default", "path to kustomization in the application repository")
	addCmd.PersistentFlags().StringVar(&addArgs.destinationBranch, "destination-branch", "main", "Git branch of the destination repository")
	addCmd.PersistentFlags().BoolVar(&addArgs.destinationPrivate, "private", true, "if true, the repository is setup or configured as private")
	addCmd.PersistentFlags().StringVar(&addArgs.fleetBranch, "fleet-branch", "main", "Git branch of the fleet repository")
	addCmd.PersistentFlags().StringArrayVar(&addArgs.values, "set-value", []string{}, "set values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)")
	addCmd.PersistentFlags().DurationVar(&addArgs.interval, "interval", time.Minute, "sync interval")
	addCmd.PersistentFlags().StringVar(&addArgs.sourceSecretName, "sourcesecret-name", "sourcesecret", "name of the source secret containing the credentials for the destination repository")
	addCmd.PersistentFlags().BoolVar(&addArgs.tokenAuth, "token-auth", false, "when enabled, the personal access token will be used instead of SSH deploy key")
	addCmd.PersistentFlags().Var(&addArgs.keyAlgorithm, "ssh-key-algorithm", addArgs.keyAlgorithm.Description())
	addCmd.PersistentFlags().Var(&addArgs.keyRSABits, "ssh-rsa-bits", addArgs.keyRSABits.Description())
	addCmd.PersistentFlags().Var(&addArgs.keyECDSACurve, "ssh-ecdsa-curve", addArgs.keyECDSACurve.Description())
	addCmd.PersistentFlags().StringVar(&addArgs.sshHostname, "ssh-hostname", "", "SSH hostname, to be used when the SSH host differs from the HTTPS one")
	addCmd.PersistentFlags().StringVar(&addArgs.caFile, "ca-file", "", "path to TLS CA file used for validating self-signed certificates")
	addCmd.PersistentFlags().StringVar(&addArgs.privateKeyFile, "private-key-file", "", "path to a private key file used for authenticating to the Git SSH server")

	addCmd.PersistentFlags().StringVar(&addArgs.authorName, "author-name", "Lizz", "author name for Git commits")
	addCmd.PersistentFlags().StringVar(&addArgs.authorEmail, "author-email", "", "author email for Git commits")

	rootCmd.AddCommand(addCmd)
}

func mapTeamSlice(s []string, defaultPermission string) map[string]string {
	m := make(map[string]string, len(s))
	for _, v := range s {
		m[v] = defaultPermission
		if s := strings.Split(v, ":"); len(s) == 2 {
			m[s[0]] = s[1]
		}
	}
	return m
}

func parseValues(values []string) (map[string]interface{}, error) {
	base := map[string]interface{}{}
	for _, value := range values {
		if err := strvals.ParseInto(value, base); err != nil {
			return nil, fmt.Errorf("failed parsing --set-value data: %w", err)
		}
	}
	// check that there is no two levels values which is not expected
	for _, value := range base {
		if _, ok := value.(string); !ok {
			return nil, fmt.Errorf("a two level value is passed in --set-value which is not expected. The two level value is %v", value)
		}
	}
	return base, nil
}
