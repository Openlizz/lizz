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
	"gitlab.com/openlizz/lizz/internal/logger/cli"
	"sigs.k8s.io/yaml"
)

type ApplicationDependency struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Print       bool   `json:"print,omitempty"`
	Repository  string `json:"repository,omitempty"`
	ShaRange    string `json:"shaRange,omitempty"`
	Value       bool   `json:"value,omitempty"`
}

type ClusterValue struct {
	Name        string `json:"name"`
	Required    bool   `json:"required,omitempty"`
	Description string `json:"description,omitempty"`
	Print       bool   `json:"print,omitempty"`
	Template    string `json:"template,omitempty"`
	Value       string `json:"value,omitempty"`
}

type ApplicationValue struct {
	Name          string `json:"name"`
	Description   string `json:"description,omitempty"`
	Print         bool   `json:"print,omitempty"`
	RepositoryUrl string `json:"repositoryUrl,omitempty"`
	Kind          string `json:"kind,omitempty"`
	ResourceName  string `json:"resourceName,omitempty"`
	Template      string `json:"template,omitempty"`
	Value         string `json:"value,omitempty"`
}
type Password struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Print       bool   `json:"print,omitempty"`
	Lenght      int    `json:"length,omitempty"`
	NumDigits   int    `json:"numDigits,omitempty"`
	NumSymbols  int    `json:"numSymbols,omitempty"`
	NoUpper     bool   `json:"noUpper,omitempty"`
	AllowRepeat bool   `json:"allowRepeat,omitempty"`
	Base64      bool   `json:"base64,omitempty"`
}

type Values struct {
	ApplicationDependencies []ApplicationDependency `json:"applicationDependencies,omitempty"`
	ClusterValues           []ClusterValue          `json:"clusterValues,omitempty"`
	ApplicationValues       []ApplicationValue      `json:"applicationValues,omitempty"`
	Passwords               []Password              `json:"passwords,omitempty"`
}

type Encryption struct {
	Enabled    bool     `json:"enabled,omitempty"`
	InputPaths []string `json:"inputPaths,omitempty"`
}

type ApplicationConfig struct {
	Name                string                           `json:"name"`
	Namespace           string                           `json:"namespace"`
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
		if clusterValue.Required == true && tpl.String() == "" {
			return &ApplicationConfig{}, fmt.Errorf(
				"cluster value with name '%s' and template '%s' cannot be resolved and is required for the application",
				clusterValue.Name,
				clusterValue.Template,
			)
		}
		v.ClusterValues[idx].Value = tpl.String()
		tv[clusterValue.Name] = tpl.String()
	}
	// render application values ?

	// render the application configuration (without the values) with the template values
	t := template.Must(template.New("applicationConfig").Parse(strings.ReplaceAll(string(y), vy, "")))
	var tpl bytes.Buffer
	err = t.Execute(&tpl, tv)
	if err != nil {
		fmt.Println("RENDER:: \n", string(y))
		fmt.Println("VALUES:: \n", string(vy))
		fmt.Println("\nWITH:: ", tv)
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
	if c.Namespace == "" {
		c.Namespace = c.Name
	}
	if c.ServiceAccountName == "" {
		c.ServiceAccountName = c.Name
	}
	// add the values (removed for rendering) to the config
	c.Values = *v
	return c, nil
}

func (c *ApplicationConfig) Check(status *cli.Status) error {
	status.Start("Check that the application can be installed ")
	defer status.End(false)
	for idx, d := range c.Dependencies {
		if d == false {
			return fmt.Errorf("dependency number %d of the application is not fulfilled", idx)
		}
	}
	status.End(true)
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
