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
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1beta2"
	"github.com/fluxcd/pkg/apis/meta"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/sethvargo/go-password/password"
	"github.com/spf13/cobra"
	"go.mozilla.org/sops/cmd/sops/codes"
	"go.mozilla.org/sops/v3"
	"go.mozilla.org/sops/v3/aes"
	"go.mozilla.org/sops/v3/age"
	"go.mozilla.org/sops/v3/cmd/sops/common"
	"go.mozilla.org/sops/v3/keys"
	"go.mozilla.org/sops/v3/keyservice"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	kustomizePatch "sigs.k8s.io/kustomize/pkg/patch"
	kustomize "sigs.k8s.io/kustomize/pkg/types"
	"sigs.k8s.io/yaml"
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

	// clone application repository
	logger.Actionf("clone application repository")
	gitClient, tmpDir, err := cloneRepositoryTemp(addArgs.originUrl, addArgs.originBranch, addArgs.username, addArgs.password, rootArgs.timeout)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	head, err := gitClient.Head()
	if err != nil {
		return err
	}
	// clone cluster repository
	logger.Actionf("clone cluster repository")
	gitClientFleet, tmpDirFleet, err := cloneRepositoryTemp(addArgs.fleetUrl, addArgs.fleetBranch, addArgs.username, addArgs.password, rootArgs.timeout)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDirFleet)
	// read application config file
	logger.Actionf("read application config file")
	_, err = os.Stat(filepath.Join(tmpDir, "config.yaml"))
	if err != nil {
		return fmt.Errorf("the application does not have a config.yaml file: %w", err)
	}
	applicationConfigData, err := os.ReadFile(filepath.Join(tmpDir, "config.yaml"))
	if err != nil {
		return err
	}
	// extract values to rendered from application config file
	logger.Actionf("extract values to rendered from application config file")
	valuesString := extractValuesFromString(string(applicationConfigData))
	values := &Values{}
	if valuesString != "" {
		err = yaml.Unmarshal([]byte(valuesString), &values)
		if err != nil {
			return err
		}
	}
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
	// initialize template values
	templateValues := make(map[string]interface{})
	// render application dependencies
	logger.Actionf("render application dependencies")
	for idx, applicationDependency := range values.ApplicationDependencies {
		templateValues[applicationDependency.Name] = false
		for _, application := range clusterConfig.Applications {
			if application.Configuration.Repository == applicationDependency.Repository {
				values.ApplicationDependencies[idx].Value = true
				delete(templateValues, applicationDependency.Name)
				templateValues[applicationDependency.Name] = true
				// check that the application.Configuration.sha is include in
				// `git rev-parse applicationDependency.shaRange`
			}
		}
	}
	// render cluster values
	logger.Actionf("render cluster values")
	for idx, clusterValue := range values.ClusterValues {
		t := template.Must(template.New("clusterValue").Parse(clusterValue.Template))
		var tpl bytes.Buffer
		err := t.Execute(&tpl, clusterConfig)
		if err != nil {
			return fmt.Errorf("error in the cluster value with name %s: %w", clusterValue.Name, err)
		}
		values.ClusterValues[idx].Value = tpl.String()
		templateValues[clusterValue.Name] = tpl.String()
	}
	// render passwords
	logger.Actionf("render passwords")
	for _, pwd := range values.Passwords {
		res, err := password.Generate(pwd.Lenght, pwd.NumDigits, pwd.NumSymbols, pwd.NoUpper, pwd.AllowRepeat)
		if err != nil {
			return err
		}
		templateValues[pwd.Name] = res
	}
	// render application values ?

	// render the application configuration file
	logger.Actionf("render the application configuration file")
	t := template.Must(template.New("applicationConfig").Parse(string(applicationConfigData)))
	var tpl bytes.Buffer
	err = t.Execute(&tpl, templateValues)
	if err != nil {
		return fmt.Errorf("error while rendering the application configuration file: %w", err)
	}
	applicationConfigString := tpl.String()
	// create ApplicationConfig struct
	logger.Actionf("create ApplicationConfig struct")
	applicationConfig := &ApplicationConfiguration{}
	err = yaml.Unmarshal([]byte(applicationConfigString), &applicationConfig)
	if err != nil {
		return err
	}
	applicationConfig.Repository = addArgs.originUrl
	applicationConfig.Sha = head
	applicationConfig.Values = *values
	// make sure all dependencies are true
	logger.Actionf("make sure all dependencies are true")
	for idx, dep := range applicationConfig.Dependencies {
		if dep == false {
			return fmt.Errorf("dependency number %d of the application is not fulfilled", idx)
		}
	}
	// render all the application files using the templateValues
	logger.Actionf("render all the application files using the templateValues")
	var applicationFilesPaths []string
	err = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() == false && strings.Index(path, ".git") == -1 {
			blackListed := false
			for _, blackListedPath := range append(applicationConfig.TemplatingBlackList, "config.yaml") {
				backListedInfo, err := os.Stat(filepath.Join(tmpDir, blackListedPath))
				if err != nil {
					return err
				}
				if os.SameFile(backListedInfo, info) {
					blackListed = true
				}
			}
			if blackListed == false {
				applicationFilesPaths = append(applicationFilesPaths, path)
			}
		}
		return nil
	})
	for _, path := range applicationFilesPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		t := template.Must(template.New("applicationFile").Parse(string(data)))
		var tpl bytes.Buffer
		err = t.Execute(&tpl, templateValues)
		if err != nil {
			return fmt.Errorf("error while rendering the application configuration file: %w", err)
		}
		file, err := os.Create(path)
		if err != nil {
			return common.NewExitError(fmt.Sprintf("Could not open in-place file for writing: %s", err), codes.CouldNotWriteOutputFile)
		}
		defer file.Close()
		_, err = file.Write(tpl.Bytes())
		if err != nil {
			return err
		}
	}
	// encrypt application secrets
	logger.Actionf("encrypt application secrets")
	if applicationConfig.Encryption.Enabled == true {
		if clusterConfig.AgeKey == "" {
			return fmt.Errorf("secret encryption needed for the application but not configured in the cluster config file")
		}
		svcs := []keyservice.KeyServiceClient{
			keyservice.NewLocalClient(),
		}
		key, err := age.MasterKeyFromRecipient(clusterConfig.AgeKey)
		if err != nil {
			return err
		}
		groups := []sops.KeyGroup{[]keys.MasterKey{key}}
		var threshold int
		for _, inputPath := range applicationConfig.Encryption.InputPaths {
			fileName := filepath.Join(tmpDir, inputPath)
			inputStore := common.DefaultStoreForPathOrFormat(fileName, "yaml")
			outputStore := common.DefaultStoreForPathOrFormat(fileName, "yaml")
			output, err := encrypt(encryptOpts{
				OutputStore:    outputStore,
				InputStore:     inputStore,
				InputPath:      fileName,
				Cipher:         aes.NewCipher(),
				EncryptedRegex: "^(data|stringData)$",
				KeyServices:    svcs,
				KeyGroups:      groups,
				GroupThreshold: threshold,
			})
			if err != nil {
				return err
			}
			file, err := os.Create(fileName)
			if err != nil {
				return common.NewExitError(fmt.Sprintf("Could not open in-place file for writing: %s", err), codes.CouldNotWriteOutputFile)
			}
			defer file.Close()
			_, err = file.Write(output)
			if err != nil {
				return err
			}
		}
	}
	// create application repository to destination
	logger.Actionf("create application repository to destination")
	err = commitAndpush(gitClient, addArgs.authorName, addArgs.authorEmail, "Initialize application repository", addArgs.originBranch, addArgs.destinationUrl, rootArgs.timeout)
	if err != nil {
		return err
	}
	head, err = gitClient.Head()
	if err != nil {
		return err
	}
	// add new application to the cluster configuration
	logger.Actionf("add new application to the cluster configuration")
	clusterConfig.Applications = appendApplicationIfMissing(clusterConfig.Applications, Application{
		Name:          applicationConfig.Name,
		Repository:    addArgs.destinationUrl,
		Configuration: *applicationConfig,
	})
	// write new configuration to file
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
	// update cluster configuration on remote
	logger.Actionf("update cluster configuration on remote")
	err = commitAndpush(gitClientFleet, addArgs.authorName, addArgs.authorEmail, "Update cluster configuration file", addArgs.fleetBranch, "", rootArgs.timeout)
	if err != nil {
		return err
	}
	// create the application folder in the cluster repository
	logger.Actionf("create the application folder in the cluster repository")
	pathToApplications := filepath.Join(tmpDirFleet, "applications")
	pathToApplicationsBase := filepath.Join(pathToApplications, "base")
	pathToApplicationsBaseApplication := filepath.Join(pathToApplicationsBase, applicationConfig.Name)
	err = os.MkdirAll(pathToApplicationsBaseApplication, os.ModePerm)
	if err != nil {
		return err
	}
	// create the rbac.yaml file
	logger.Actionf("create the rbac.yaml file")
	tenant := applicationConfig.Name
	ns := applicationConfig.Name
	clusterRole := "cluster-admin"
	var serviceAccountName string
	if applicationConfig.ServiceAccountName != "" {
		serviceAccountName = applicationConfig.ServiceAccountName
	} else {
		serviceAccountName = tenant
	}
	if err := validation.IsQualifiedName(tenant); len(err) > 0 {
		return fmt.Errorf("invalid tenant name '%s': %v", tenant, err)
	}
	if err := validation.IsQualifiedName(ns); len(err) > 0 {
		return fmt.Errorf("invalid namespace '%s': %v", ns, err)
	}
	if err := validation.IsQualifiedName(serviceAccountName); len(err) > 0 {
		return fmt.Errorf("invalid service account name '%s': %v", ns, err)
	}
	objLabels := make(map[string]string)
	objLabels[tenantLabel] = tenant
	namespace := corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   ns,
			Labels: objLabels,
		},
	}
	account := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName,
			Namespace: ns,
			Labels:    objLabels,
		},
	}
	var rbac string
	if addArgs.clusterRole {
		clusterRoleBinding := rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-reconciler", tenant),
				Namespace: ns,
				Labels:    objLabels,
			},
			Subjects: []rbacv1.Subject{
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "User",
					Name:     fmt.Sprintf("gotk:%s:reconciler", ns),
				},
				{
					Kind:      "ServiceAccount",
					Name:      serviceAccountName,
					Namespace: ns,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     clusterRole,
			},
		}
		rbac, err = exportTenantWithClusterRoleBinding(namespace, account, clusterRoleBinding)
	} else {
		roleBinding := rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-reconciler", tenant),
				Namespace: ns,
				Labels:    objLabels,
			},
			Subjects: []rbacv1.Subject{
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "User",
					Name:     fmt.Sprintf("gotk:%s:reconciler", ns),
				},
				{
					Kind:      "ServiceAccount",
					Name:      serviceAccountName,
					Namespace: ns,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     clusterRole,
			},
		}
		rbac, err = exportTenantWithRoleBinding(namespace, account, roleBinding)
	}
	if err != nil {
		return err
	}
	f, err = os.Create(filepath.Join(pathToApplicationsBaseApplication, "rbac.yaml"))
	if err != nil {
		return err
	}
	l, err = f.WriteString(rbac)
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
	// create the sync.yaml file
	logger.Actionf("create the sync.yaml file")
	name := applicationConfig.Name
	u, err := url.Parse(addArgs.destinationUrl)
	if err != nil {
		return fmt.Errorf("git URL parse failed: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("git URL scheme '%s' not supported, can be: http and https", u.Scheme)
	}
	gitRepository := sourcev1.GitRepository{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: sourcev1.GitRepositorySpec{
			Interval: metav1.Duration{
				Duration: 5 * time.Minute,
			},
			URL:       addArgs.destinationUrl,
			Reference: &sourcev1.GitRepositoryRef{Branch: "main"},
		},
	}
	var decryption *kustomizev1.Decryption
	if applicationConfig.Encryption.Enabled == true {
		decryption = &kustomizev1.Decryption{
			Provider:  "sops",
			SecretRef: &meta.LocalObjectReference{Name: addArgs.decryptionSecret},
		}
	}
	kustomization := kustomizev1.Kustomization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: kustomizev1.KustomizationSpec{
			ServiceAccountName: serviceAccountName,
			DependsOn:          applicationConfig.DependsOn,
			Interval: metav1.Duration{
				Duration: 5 * time.Minute,
			},
			Prune: true,
			SourceRef: kustomizev1.CrossNamespaceSourceReference{
				Kind: "GitRepository",
				Name: name,
			},
			Validation: "client",
			Decryption: decryption,
		},
	}
	sync, err := exportRepository(gitRepository, kustomization)
	if err != nil {
		return err
	}
	f, err = os.Create(filepath.Join(pathToApplicationsBaseApplication, "sync.yaml"))
	if err != nil {
		return err
	}
	l, err = f.WriteString(sync)
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
	// create secret.yaml
	if applicationConfig.Encryption.Enabled == true {
		logger.Actionf("create secret.yaml")
		f, err = os.Create(filepath.Join(pathToApplicationsBaseApplication, "secret.yaml"))
		if err != nil {
			return err
		}
		l, err = f.WriteString(strings.Replace(clusterConfig.SopsAgeSecret, "namespace: flux-system", "namespace: "+ns, 1))
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
	}
	// create the kustomization.yaml file
	logger.Actionf("create the kustomization.yaml file")
	var resources []string
	if applicationConfig.Encryption.Enabled == true {
		resources = []string{"rbac.yaml", "sync.yaml", "secret.yaml"}
	} else {
		resources = []string{"rbac.yaml", "sync.yaml"}
	}
	kustom := kustomize.Kustomization{
		Resources: resources,
	}
	kustomString, err := exportKustomization(kustom)
	if err != nil {
		return err
	}
	f, err = os.Create(filepath.Join(pathToApplicationsBaseApplication, "kustomization.yaml"))
	if err != nil {
		return err
	}
	l, err = f.WriteString(kustomString)
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
	// create the patch file
	logger.Actionf("create the patch file")
	applicationPatch := kustomizev1.Kustomization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: kustomizev1.KustomizationSpec{
			Path: addArgs.path,
		},
	}
	patch, err := exportPatch(applicationPatch)
	if err != nil {
		return err
	}
	f, err = os.Create(filepath.Join(pathToApplications, applicationConfig.Name+"-patch.yaml"))
	if err != nil {
		return err
	}
	l, err = f.WriteString(patch)
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
	// add the application to the applications.yaml file
	logger.Actionf("add the application to the applications.yaml file")
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
	}
	applications.Resources = appendStringIfMissing(applications.Resources, "./base/"+applicationConfig.Name)
	applications.PatchesStrategicMerge = appendStrategicMergeIfMissing(applications.PatchesStrategicMerge, kustomizePatch.StrategicMerge(applicationConfig.Name+"-patch.yaml"))
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
	// push all the application files to the remote cluster repository
	logger.Actionf("push all the application files to the remote cluster repository")
	err = commitAndpush(gitClientFleet, addArgs.authorName, addArgs.authorEmail, "Update cluster configuration file", addArgs.fleetBranch, "", rootArgs.timeout)
	if err != nil {
		return err
	}
	return nil
}

func exportTenantWithRoleBinding(namespace corev1.Namespace, account corev1.ServiceAccount, roleBinding rbacv1.RoleBinding) (string, error) {
	var builder strings.Builder
	namespace.TypeMeta = metav1.TypeMeta{
		APIVersion: "v1",
		Kind:       "Namespace",
	}
	data, err := yaml.Marshal(namespace)
	if err != nil {
		return "", err
	}

	builder.WriteString("---\n")
	data = bytes.Replace(data, []byte("spec: {}\n"), []byte(""), 1)
	builder.WriteString(resourceToString(data))

	account.TypeMeta = metav1.TypeMeta{
		APIVersion: "v1",
		Kind:       "ServiceAccount",
	}
	data, err = yaml.Marshal(account)
	if err != nil {
		return "", err
	}

	builder.WriteString("---\n")
	data = bytes.Replace(data, []byte("spec: {}\n"), []byte(""), 1)
	builder.WriteString(resourceToString(data))

	roleBinding.TypeMeta = metav1.TypeMeta{
		APIVersion: "rbac.authorization.k8s.io/v1",
		Kind:       "RoleBinding",
	}
	data, err = yaml.Marshal(roleBinding)
	if err != nil {
		return "", err
	}

	builder.WriteString("---\n")
	builder.WriteString(resourceToString(data))

	return builder.String(), nil
}

func exportTenantWithClusterRoleBinding(namespace corev1.Namespace, account corev1.ServiceAccount, clusterRoleBinding rbacv1.ClusterRoleBinding) (string, error) {
	var builder strings.Builder
	namespace.TypeMeta = metav1.TypeMeta{
		APIVersion: "v1",
		Kind:       "Namespace",
	}
	data, err := yaml.Marshal(namespace)
	if err != nil {
		return "", err
	}

	builder.WriteString("---\n")
	data = bytes.Replace(data, []byte("spec: {}\n"), []byte(""), 1)
	builder.WriteString(resourceToString(data))

	account.TypeMeta = metav1.TypeMeta{
		APIVersion: "v1",
		Kind:       "ServiceAccount",
	}
	data, err = yaml.Marshal(account)
	if err != nil {
		return "", err
	}

	builder.WriteString("---\n")
	data = bytes.Replace(data, []byte("spec: {}\n"), []byte(""), 1)
	builder.WriteString(resourceToString(data))

	clusterRoleBinding.TypeMeta = metav1.TypeMeta{
		APIVersion: "rbac.authorization.k8s.io/v1",
		Kind:       "ClusterRoleBinding",
	}
	data, err = yaml.Marshal(clusterRoleBinding)
	if err != nil {
		return "", err
	}

	builder.WriteString("---\n")
	builder.WriteString(resourceToString(data))

	return builder.String(), nil
}

func exportRepository(gitRepository sourcev1.GitRepository, kustomization kustomizev1.Kustomization) (string, error) {
	var builder strings.Builder
	gitRepository.TypeMeta = metav1.TypeMeta{
		APIVersion: "source.toolkit.fluxcd.io/v1beta1",
		Kind:       "GitRepository",
	}
	data, err := yaml.Marshal(gitRepository)
	if err != nil {
		return "", err
	}
	builder.WriteString(resourceToString(data))
	kustomization.TypeMeta = metav1.TypeMeta{
		APIVersion: "kustomize.toolkit.fluxcd.io/v1beta2",
		Kind:       "Kustomization",
	}
	data, err = yaml.Marshal(kustomization)
	if err != nil {
		return "", err
	}
	builder.WriteString("---\n")
	builder.WriteString(resourceToString(data))
	return builder.String(), nil
}

func exportKustomization(kustomization kustomize.Kustomization) (string, error) {
	var builder strings.Builder
	kustomization.TypeMeta = kustomize.TypeMeta{
		APIVersion: "kustomize.config.k8s.io/v1beta1",
		Kind:       "Kustomization",
	}
	data, err := yaml.Marshal(kustomization)
	if err != nil {
		return "", err
	}
	builder.WriteString(resourceToString(data))
	return builder.String(), nil
}

func exportPatch(kustomization kustomizev1.Kustomization) (string, error) {
	var builder strings.Builder
	kustomization.TypeMeta = metav1.TypeMeta{
		APIVersion: "kustomize.toolkit.fluxcd.io/v1beta2",
		Kind:       "Kustomization",
	}
	data, err := yaml.Marshal(kustomization)
	if err != nil {
		return "", err
	}
	data = bytes.Replace(data, []byte("interval: 0s\n"), []byte(""), 1)
	data = bytes.Replace(data, []byte("prune: false\n"), []byte(""), 1)
	data = bytes.Replace(data, []byte("sourceRef:\n"), []byte(""), 1)
	data = bytes.Replace(data, []byte("kind: \"\"\n"), []byte(""), 1)
	data = bytes.Replace(data, []byte("name: \"\"\n"), []byte(""), 1)
	builder.WriteString(resourceToString(data))
	return builder.String(), nil
}
