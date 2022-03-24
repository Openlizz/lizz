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
	"os"
	"path/filepath"
	"time"

	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1beta2"
	"github.com/fluxcd/pkg/apis/meta"
	"go.mozilla.org/sops/v3/aes"
	sopsAge "go.mozilla.org/sops/v3/age"
	"go.mozilla.org/sops/v3/cmd/sops/common"
	"go.mozilla.org/sops/v3/keys"
	"go.mozilla.org/sops/v3/keyservice"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"go.mozilla.org/sops/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

var secretManagementConfigurationCmd = &cobra.Command{
	Use:   "secret-management-configuration",
	Short: "",
	Long:  ``,
	RunE:  secretManagementConfigurationCmdRun,
}

type secretManagementConfigurationFlags struct {
	output           string
	path             string
	decryptionSecret string
	fleetUrl         string
	fleetBranch      string
	interval         time.Duration
	username         string
	password         string
	silent           bool

	authorName  string
	authorEmail string
}

var secretManagementConfigurationArgs secretManagementConfigurationFlags

func init() {
	secretManagementConfigurationCmd.Flags().StringVarP(&secretManagementConfigurationArgs.output, "ouput", "o", "sopsAgeSecret.yaml", "output where to save the secret to apply")
	secretManagementConfigurationCmd.Flags().StringVar(&secretManagementConfigurationArgs.path, "path", "cluster/applications.yaml", "path to the applications yaml file")
	secretManagementConfigurationCmd.Flags().StringVar(&secretManagementConfigurationArgs.decryptionSecret, "decryptionSecret", "sops-age", "name of the secret containing the AGE secret key")
	secretManagementConfigurationCmd.Flags().StringVar(&secretManagementConfigurationArgs.fleetUrl, "fleetUrl", "", "Git repository URL of the fleet repository")
	secretManagementConfigurationCmd.Flags().StringVar(&secretManagementConfigurationArgs.fleetBranch, "fleetBranch", "main", "Git branch of the fleet repository")
	secretManagementConfigurationCmd.Flags().DurationVar(&secretManagementConfigurationArgs.interval, "interval", time.Minute, "sync interval")
	secretManagementConfigurationCmd.Flags().StringVarP(&secretManagementConfigurationArgs.username, "username", "u", "git", "basic authentication username")
	secretManagementConfigurationCmd.Flags().StringVarP(&secretManagementConfigurationArgs.password, "password", "p", "", "basic authentication password")
	secretManagementConfigurationCmd.Flags().BoolVarP(&secretManagementConfigurationArgs.silent, "silent", "s", false, "assumes the deploy key is already setup, skips confirmation")

	secretManagementConfigurationCmd.Flags().StringVar(&secretManagementConfigurationArgs.authorName, "author-name", "Lizz", "author name for Git commits")
	secretManagementConfigurationCmd.Flags().StringVar(&secretManagementConfigurationArgs.authorEmail, "author-email", "", "author email for Git commits")

	rootCmd.AddCommand(secretManagementConfigurationCmd)
}

func secretManagementConfigurationCmdRun(cmd *cobra.Command, args []string) error {

	// generate Age key (code from https://github.com/FiloSottile/age/blob/4169274d045d1ca198e09ef40d317cb6a5dfb7c4/cmd/age-keygen/keygen.go#L123)
	logger.Actionf("generate Age key")
	k, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("internal error: %v", err)
	}
	// create the secret from the Age key
	logger.Actionf("create the secret from the Age key")
	agekey := fmt.Sprintf("# created: %s\n", time.Now().Format(time.RFC3339))
	agekey += fmt.Sprintf("# public key: %s\n", k.Recipient())
	agekey += fmt.Sprintf("%s\n", k)
	sopsAgeSecret := corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretManagementConfigurationArgs.decryptionSecret,
			Namespace: "flux-system",
		},
		Data: map[string][]byte{"age.agekey": []byte(agekey)},
	}
	// save secret to ouput file
	logger.Actionf("save secret to ouput file")
	var out *os.File
	outFlag := secretManagementConfigurationArgs.output
	if outFlag != "" {
		f, err := os.OpenFile(outFlag, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("failed to open output file %q: %v", outFlag, err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				logger.Failuref("failed to close output file %q: %v", outFlag, err)
			}
		}()
		out = f
	} else {
		return fmt.Errorf("output flag cannot be empty")
	}
	sopsAgeSecretString, err := yaml.Marshal(sopsAgeSecret)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, string(sopsAgeSecretString))
	// encrypt private key secret
	logger.Actionf("encrypt private key secret")
	svcs := []keyservice.KeyServiceClient{
		keyservice.NewLocalClient(),
	}
	key, err := sopsAge.MasterKeyFromRecipient(k.Recipient().String())
	if err != nil {
		return err
	}
	groups := []sops.KeyGroup{[]keys.MasterKey{key}}
	var threshold int
	fileName := outFlag
	inputStore := common.DefaultStoreForPathOrFormat(fileName, "yaml")
	outputStore := common.DefaultStoreForPathOrFormat(fileName, "yaml")
	sopsAgeSecretEncrypted, err := encrypt(encryptOpts{
		OutputStore:    outputStore,
		InputStore:     inputStore,
		InputPath:      fileName,
		Cipher:         aes.NewCipher(),
		EncryptedRegex: "^(data|stringData)$",
		KeyServices:    svcs,
		KeyGroups:      groups,
		GroupThreshold: threshold,
	})
	// clone cluster repository
	logger.Actionf("clone cluster repository")
	gitClientFleet, tmpDirFleet, err := cloneRepositoryTemp(secretManagementConfigurationArgs.fleetUrl, secretManagementConfigurationArgs.fleetBranch, secretManagementConfigurationArgs.username, secretManagementConfigurationArgs.password, rootArgs.timeout)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDirFleet)
	// read the cluster config file
	logger.Actionf("read the cluster config file")
	_, err = os.Stat(filepath.Join(tmpDirFleet, "config.yaml"))
	if err != nil {
		return fmt.Errorf("the cluster does not have a config.yaml file: %w", err)
	}
	clusterConfigData, err := os.ReadFile(filepath.Join(tmpDirFleet, "config.yaml"))
	if err != nil {
		return err
	}
	// create ClusterConfig struct
	logger.Actionf("create ClusterConfig struct")
	clusterConfig := &ClusterConfig{}
	err = yaml.Unmarshal([]byte(clusterConfigData), &clusterConfig)
	if err != nil {
		return err
	}
	// add the public key to the configuration
	logger.Actionf("add the public key to the configuration")
	if clusterConfig.AgeKey != "" || clusterConfig.SopsAgeSecret != "" {
		return fmt.Errorf("the cluster already has an age key configured")
	}
	clusterConfig.AgeKey = k.Recipient().String()
	clusterConfig.SopsAgeSecret = string(sopsAgeSecretEncrypted)
	// updated the cluster configuration file
	logger.Actionf("updated the cluster configuration file")
	clusterConfigData, err = yaml.Marshal(clusterConfig)
	if err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(tmpDirFleet, "config.yaml"))
	if err != nil {
		return err
	}
	l, err := f.WriteString(string(clusterConfigData))
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
	// read the cluster applications file
	logger.Actionf("read the cluster applications file")
	pathToApplications := filepath.Join(tmpDirFleet, secretManagementConfigurationArgs.path)
	_, err = os.Stat(pathToApplications)
	if err != nil {
		return fmt.Errorf("the cluster does not have a applications.yaml file: %w", err)
	}
	applicationsData, err := os.ReadFile(pathToApplications)
	if err != nil {
		return err
	}
	// create applications Kustomization
	logger.Actionf("create applications Kustomization")
	applications := &kustomizev1.Kustomization{}
	err = yaml.Unmarshal([]byte(applicationsData), &applications)
	if err != nil {
		return err
	}
	// add decryption to the applications
	logger.Actionf("add decryption to the applications")
	if applications.Spec.Decryption != nil {
		return fmt.Errorf("decryption is already configured")
	}
	applications.Spec.Decryption = &kustomizev1.Decryption{
		Provider:  "sops",
		SecretRef: &meta.LocalObjectReference{Name: secretManagementConfigurationArgs.decryptionSecret},
	}
	// updated the cluster applications file
	logger.Actionf("updated the cluster applications file")
	applicationsData, err = yaml.Marshal(applications)
	if err != nil {
		return err
	}
	f, err = os.Create(pathToApplications)
	if err != nil {
		return err
	}
	l, err = f.WriteString(string(applicationsData))
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
	// push changes to the remote cluster repository
	logger.Actionf("push changes to the remote cluster repository")
	err = commitAndpush(gitClientFleet, addArgs.authorName, addArgs.authorEmail, "Added secret management support", addArgs.fleetBranch, "", rootArgs.timeout)
	if err != nil {
		return err
	}
	return nil
}
