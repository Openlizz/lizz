package config

import (
	"bytes"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/fluxcd/pkg/apis/meta"
	"sigs.k8s.io/yaml"
)

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
type Password struct {
	Name        string `json:"name"`
	Lenght      int    `json:"length"`
	NumDigits   int    `json:"numDigits"`
	NumSymbols  int    `json:"numSymbols"`
	NoUpper     bool   `json:"noUpper"`
	AllowRepeat bool   `json:"allowRepeat"`
}

type Values struct {
	ApplicationDependencies []ApplicationDependency `json:"applicationDependencies,omitempty"`
	ClusterValues           []ClusterValue          `json:"clusterValues,omitempty"`
	ApplicationValues       []ApplicationValue      `json:"applicationValues,omitempty"`
	Passwords               []Password              `json:"passwords,omitempty"`
}

type Encryption struct {
	Enabled    bool     `json:"enabled"`
	InputPaths []string `json:"inputPaths"`
}

type ApplicationConfig struct {
	Name                string                           `json:"name"`
	ServiceAccountName  string                           `json:"serviceAccountName"`
	Repository          string                           `json:"repository"`
	Sha                 string                           `json:"sha"`
	Values              Values                           `json:"values,omitempty"`
	TemplatingBlackList []string                         `json:"templatingBlackList,omitempty"`
	Encryption          Encryption                       `json:"encryption,omitempty"`
	Dependencies        []bool                           `json:"dependencies,omitempty"`
	DependsOn           []meta.NamespacedObjectReference `json:"dependsOn,omitempty"`
}

func OpenApplicationConfig(path string) (*ApplicationConfig, error) {
	_, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("The path to the cluster config does not exist: %w.", err)
	}
	y, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &ApplicationConfig{}
	err = yaml.Unmarshal([]byte(y), &c)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func RenderApplicationConfig(
	path string,
	clusterConfig *ClusterConfig,
) (*ApplicationConfig, error) {
	_, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("The path to the cluster config does not exist: %w.", err)
	}
	y, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	vy := extractValuesFromYaml(string(y))
	v := &Values{}
	if vy != "" {
		err := yaml.Unmarshal([]byte(vy), &v)
		if err != nil {
			return &ApplicationConfig{}, err
		}
	}
	tv := make(map[string]interface{})
	// render application dependencies
	for idx, ad := range v.ApplicationDependencies {
		tv[ad.Name] = false
		for _, application := range clusterConfig.Applications {
			if application.Configuration.Repository == ad.Repository {
				v.ApplicationDependencies[idx].Value = true
				delete(tv, ad.Name)
				tv[ad.Name] = true
				// check that the application.Configuration.sha is include in
				// `git rev-parse applicationDependency.shaRange`
			}
		}
	}
	// render cluster values
	for idx, clusterValue := range v.ClusterValues {
		t := template.Must(template.New("clusterValue").Parse(clusterValue.Template))
		var tpl bytes.Buffer
		err := t.Execute(&tpl, clusterConfig)
		if err != nil {
			return &ApplicationConfig{}, fmt.Errorf(
				"error in the cluster value with name %s: %w",
				clusterValue.Name,
				err,
			)
		}
		v.ClusterValues[idx].Value = tpl.String()
		tv[clusterValue.Name] = tpl.String()
	}
	// render application values ?

	// render the application configuration with the template values
	t := template.Must(template.New("applicationConfig").Parse(string(y)))
	var tpl bytes.Buffer
	err = t.Execute(&tpl, tv)
	if err != nil {
		return &ApplicationConfig{}, fmt.Errorf(
			"error while rendering the application configuration file: %w",
			err,
		)
	}
	c := &ApplicationConfig{}
	err = yaml.Unmarshal([]byte(tpl.String()), c)
	if err != nil {
		return &ApplicationConfig{}, err
	}
	return c, nil
}

func (c *ApplicationConfig) Check() error {
	for idx, d := range c.Dependencies {
		if d == false {
			return fmt.Errorf("dependency number %d of the application is not fulfilled", idx)
		}
	}
	return nil
}

func (c *ApplicationConfig) Save(path string) error {
	y, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	l, err := f.WriteString(string(y))
	if err != nil {
		f.Close()
		return err
	}
	if l == 0 {
		return fmt.Errorf("cluster config file saved but empty.")
	}
	err = f.Close()
	if err != nil {
		return err
	}
	return nil
}

func extractValuesFromYaml(config string) string {
	startIndex := strings.Index(config, "values:")
	if startIndex == -1 {
		// TODO
		// no values -> check that dependencies and dependsOn are also empty
		return ""
	} else {
		startIndex += len("values:")
		r, _ := regexp.Compile("\n[^( \t)]")
		endIndex := r.FindStringIndex(config[startIndex:])
		if endIndex == nil {
			endIndex = []int{len(config) - startIndex}
		}
		return strings.ReplaceAll(config[startIndex:startIndex+endIndex[0]], "\t", "  ")
	}
}

func UniversalURL(URL string) (string, error) {
	uURL, err := url.Parse(URL)
	if err != nil {
		return "", fmt.Errorf("git URL parse failed: %w", err)
	}
	host := uURL.Host
	path := uURL.Path
	if path[len(path)-4:] == ".git" {
		path = path[:len(path)-4]
	}
	return host + path, nil
}
