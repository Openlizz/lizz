package cmd

import (
	"github.com/fluxcd/pkg/runtime/dependency"
)

type Spec struct {
	RepositoryUrl string `json:"repositoryUrl"`
	ShaRange      string `json:"shaRange"`
	template      string `json:"template"`
}

type ApplicationDependency struct {
	Name       string `json:"name"`
	Repository string `json:"repository"`
	ShaRange   string `json:"shaRange"`
	Value      bool   `json:"value"`
}

type ClusterValue struct {
	Name     string `json:"name"`
	Template string `json:"template"`
	Value    string `json:"value"`
}

type ApplicationValue struct {
	Name          string `json:"name"`
	RepositoryUrl string `json:"repositoryUrl"`
	Kind          string `json:"kind"`
	ResourceName  string `json:"resourceName"`
	Template      string `json:"template"`
	Value         string `json:"value"`
}

type Values struct {
	ApplicationDependencies []ApplicationDependency `json:"applicationDependencies,omitempty"`
	ClusterValues           []ClusterValue          `json:"clusterValues,omitempty"`
	ApplicationValues       []ApplicationValue      `json:"applicationValues,omitempty"`
}

type ApplicationConfiguration struct {
	Name               string                                         `json:"name"`
	ServiceAccountName string                                         `json:"serviceAccountName"`
	Repository         string                                         `json:"repository"`
	Sha                string                                         `json:"sha"`
	Values             Values                                         `json:"values,omitempty"`
	Dependencies       []bool                                         `json:"dependencies,omitempty"`
	DependsOn          []dependency.CrossNamespaceDependencyReference `json:"dependsOn,omitempty"`
}

type Application struct {
	Name          string                   `json:"name"`
	Repository    string                   `json:"repository"`
	Configuration ApplicationConfiguration `json:"configuration"`
}

type Configuration struct {
	Repository string `json:"repository"`
	Sha        string `json:"sha"`
}

type ClusterConfig struct {
	Repository     string          `json:"repository"`
	Sha            string          `json:"sha"`
	Applications   []Application   `json:"applications,omitempty"`
	Configurations []Configuration `json:"configurations,omitempty"`
}
