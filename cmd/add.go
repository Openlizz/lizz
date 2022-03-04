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
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	"github.com/spf13/cobra"
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
	originUrl      string
	originBranch   string
	clusterRole    bool
	path           string
	destinationUrl string
	fleetUrl       string
	fleetBranch    string
	interval       time.Duration
	username       string
	password       string
	silent         bool

	authorName  string
	authorEmail string
}

var addArgs addFlags

func init() {
	addCmd.Flags().StringVar(&addArgs.originUrl, "originUrl", "", "Git repository URL where the application is located")
	addCmd.Flags().StringVar(&addArgs.originBranch, "originBranch", "main", "Git branch of the application origin repository")
	addCmd.Flags().BoolVar(&addArgs.clusterRole, "clusterRole", false, "assumes the deploy key is already setup, skips confirmation")
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
	gitClientFleet, tmpDirFleet, err := cloneRepositoryTemp(addArgs.fleetUrl, addArgs.fleetBranch, addArgs.username, addArgs.password, rootArgs.timeout)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDirFleet)
	// read application config file
	_, err = os.Stat(filepath.Join(tmpDir, "config.yaml"))
	if err != nil {
		return fmt.Errorf("the application does not have a config.yaml file: %w", err)
	}
	applicationConfigData, err := os.ReadFile(filepath.Join(tmpDir, "config.yaml"))
	if err != nil {
		return err
	}
	// extract values to rendered from application config file
	valuesString := extractValuesFromString(string(applicationConfigData))
	values := &Values{}
	err = yaml.Unmarshal([]byte(valuesString), &values)
	if err != nil {
		return err
	}
	// read the cluster config file
	_, err = os.Stat(filepath.Join(tmpDirFleet, "config.yaml"))
	if err != nil {
		return fmt.Errorf("the cluster does not have a config.yaml file: %w", err)
	}
	clusterConfigData, err := os.ReadFile(filepath.Join(tmpDirFleet, "config.yaml"))
	if err != nil {
		return err
	}
	// create ClusterConfig struct
	clusterConfig := &ClusterConfig{}
	err = yaml.Unmarshal([]byte(clusterConfigData), &clusterConfig)
	if err != nil {
		return err
	}
	// render application dependencies
	fmt.Printf("Application dependencies: %+v\n", values.ApplicationDependencies)
	fmt.Printf("Cluster applications: %+v\n", clusterConfig.Applications)
	for _, applicationDependency := range values.ApplicationDependencies {
		for _, application := range clusterConfig.Applications {
			if application.Configuration.Repository == applicationDependency.Repository {
				fmt.Println("MATCHHHHHH")
				applicationDependency.Value = true
			}
		}
	}
	fmt.Printf("Application dependencies: %+v\n", values.ApplicationDependencies)
	// render cluster values
	fmt.Printf("Cluster values: %+v\n", values.ClusterValues)
	for _, clusterValue := range values.ClusterValues {
		t := template.Must(template.New("clusterValue").Parse(clusterValue.Template))
		var tpl bytes.Buffer
		err := t.Execute(&tpl, clusterConfig)
		if err != nil {
			return fmt.Errorf("error in the cluster value with name %s: %w", clusterValue.Name, err)
		}
		fmt.Println("New clusterValue: %s", tpl.String())
		clusterValue.Value = tpl.String()
	}
	fmt.Printf("Cluster values: %+v\n", values.ClusterValues)
	// render application values ?

	// create ApplicationConfig struct
	applicationConfig := &ApplicationConfiguration{}
	err = yaml.Unmarshal([]byte(applicationConfigData), &applicationConfig)
	if err != nil {
		return err
	}
	applicationConfig.Repository = addArgs.originUrl
	applicationConfig.Sha = head

	// applicationConfigYaml, err := yaml.Marshal(applicationConfig)
	// if err != nil {
	// 	return err
	// }
	// fmt.Println(string(applicationConfigYaml))

	// --> return here <--
	return nil

	// f, err := os.Create(filepath.Join(tmpDir, "config.yaml"))
	// if err != nil {
	// return err
	// }
	// l, err := f.WriteString(string(applicationConfigYaml))
	// if err != nil {
	// f.Close()
	// return err
	// }
	// if l > 0 {
	// logger.Successf("created file")
	// }
	// err = f.Close()
	// if err != nil {
	// return err
	// }
	// logger.Actionf("committing and pushing application configuration file")
	err = commitAndpush(gitClient, addArgs.authorName, addArgs.authorEmail, "Initialize application repository", addArgs.originBranch, addArgs.destinationUrl, rootArgs.timeout)
	if err != nil {
		return err
	}
	head, err = gitClient.Head()
	if err != nil {
		return err
	}

	/////////////////////////////
	// Update Fleet repository //
	/////////////////////////////

	logger.Actionf("updating cluster config file")
	clusterConfig.Applications = appendApplicationIfMissing(clusterConfig.Applications, Application{
		Name:       applicationConfig.Name,
		Repository: addArgs.destinationUrl,
	})
	clusterConfigYaml, err := yaml.Marshal(clusterConfig)
	if err != nil {
		return err
	}
	f, err = os.Create(filepath.Join(tmpDirFleet, "config.yaml"))
	if err != nil {
		return err
	}
	l, err = f.WriteString(string(clusterConfigYaml))
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
	err = commitAndpush(gitClientFleet, addArgs.authorName, addArgs.authorEmail, "Update cluster configuration file", addArgs.fleetBranch, "", rootArgs.timeout)
	if err != nil {
		return err
	}
	pathToApplications := filepath.Join(tmpDirFleet, "applications")
	pathToApplicationsBase := filepath.Join(pathToApplications, "base")
	pathToApplicationsBaseApplication := filepath.Join(pathToApplicationsBase, applicationConfig.Name)
	err = os.MkdirAll(pathToApplicationsBaseApplication, os.ModePerm)
	if err != nil {
		return err
	}

	////////////////////////////
	// Create new tenant file
	logger.Actionf("creating tenant configuration file")
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
	////////////////////////////
	// Create source git file
	logger.Actionf("creating source git file")
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
	kustomization := kustomizev1.Kustomization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Spec: kustomizev1.KustomizationSpec{
			ServiceAccountName: serviceAccountName,
			// DependsOn: utils.MakeDependsOn(kustomizationArgs.dependsOn),
			Interval: metav1.Duration{
				Duration: 5 * time.Minute,
			},
			Prune: true,
			SourceRef: kustomizev1.CrossNamespaceSourceReference{
				Kind: "GitRepository",
				Name: name,
			},
			Validation: "client",
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
	////////////////////////////
	// Create kustomization file
	logger.Actionf("creating kustomization file")
	kustom := kustomize.Kustomization{
		Resources: []string{"rbac.yaml", "sync.yaml"},
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
	///////////////////////
	// Create patch file
	logger.Actionf("creating application patch file")
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
	////////////////////////////////////////
	// Create or update applications file
	logger.Actionf("creating applications file")
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
	logger.Actionf("committing and pushing application files to fleet repository")
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
