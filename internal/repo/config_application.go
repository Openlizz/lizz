package repo

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/fluxcd/go-git-providers/gitprovider"
	"github.com/fluxcd/pkg/apis/meta"
	"github.com/sethvargo/go-password/password"
	"github.com/openlizz/lizz/internal/logger/cli"
	yaml2 "gopkg.in/yaml.v2"
	"helm.sh/helm/v3/pkg/strvals"
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

type UserValue struct {
	Name     string      `json:"name"`
	Required bool        `json:"required,omitempty"`
	Value    interface{} `json:"value,omitempty"`
}

type ClusterValue struct {
	Name        string      `json:"name"`
	Required    bool        `json:"required,omitempty"`
	Description string      `json:"description,omitempty"`
	Print       bool        `json:"print,omitempty"`
	Template    string      `json:"template,omitempty"`
	Value       interface{} `json:"value,omitempty"`
}

type ApplicationValue struct {
	Name       string      `json:"name"`
	Required   bool        `json:"required,omitempty"`
	Repository string      `json:"repository,omitempty"`
	Path       string      `json:"path,omitempty"`
	Keys       []string    `json:"keys,omitempty"`
	Value      interface{} `json:"value,omitempty"`
}

type ApplicationSecret struct {
	Repository        string                      `json:"repository,omitempty"`
	OriginPath        string                      `json:"originPath,omitempty"`
	DestinationPath   string                      `json:"destinationPath,omitempty"`
	KustomizationPath string                      `json:"kustomizationPath,omitempty"`
	Secret            map[interface{}]interface{} `json:"-"`
}

type Password struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Print       bool        `json:"print,omitempty"`
	Lenght      int         `json:"length,omitempty"`
	NumDigits   int         `json:"numDigits,omitempty"`
	NumSymbols  int         `json:"numSymbols,omitempty"`
	NoUpper     bool        `json:"noUpper,omitempty"`
	AllowRepeat bool        `json:"allowRepeat,omitempty"`
	Base64      bool        `json:"base64,omitempty"`
	Value       interface{} `json:"value,omitempty"`
}

type Values struct {
	ApplicationDependencies []ApplicationDependency `json:"applicationDependencies,omitempty"`
	UserValues              []UserValue             `json:"userValues,omitempty"`
	ClusterValues           []ClusterValue          `json:"clusterValues,omitempty"`
	ApplicationValues       []ApplicationValue      `json:"applicationValues,omitempty"`
	ApplicationSecrets      []ApplicationSecret     `json:"applicationSecrets,omitempty"`
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
	TransportType       gitprovider.TransportType        `json:"transportType"`
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
		return &ApplicationConfig{}, fmt.Errorf("the path to the application config does not exist: %w", err)
	}
	y, err := os.ReadFile(path)
	if err != nil {
		return &ApplicationConfig{}, err
	}
	c := &ApplicationConfig{}
	err = yaml.Unmarshal([]byte(y), &c)
	if err != nil {
		return &ApplicationConfig{}, err
	}
	return c, nil
}

func OpenApplicationFile(path string) (map[interface{}]interface{}, error) {
	_, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("the path to the application file does not exist: %w", err)
	}
	y, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f := make(map[interface{}]interface{})
	err = yaml2.Unmarshal([]byte(y), &f)
	if err != nil {
		return nil, fmt.Errorf("error while reading the Yaml file: %w", err)
	}
	return f, nil
}

func GetValueFromMap(obj map[interface{}]interface{}, keys []string) (interface{}, error) {
	var value interface{}
	var ok bool
	for idx, key := range keys {
		if idx+1 == len(keys) {
			value, ok = obj[key]
		} else {
			obj, ok = obj[key].(map[interface{}]interface{})
		}
		if ok == false {
			return "", fmt.Errorf("key `%v` not present in map `%v`", key, obj)
		}
	}
	return value, nil
}

func RenderApplicationConfig(
	path string,
	values []string,
	clusterConfig *ClusterConfig,
	cloneOptions *CloneOptions,
	status *cli.Status,
) (*ApplicationConfig, error) {
	_, err := os.Stat(path)
	if err != nil {
		return &ApplicationConfig{}, fmt.Errorf("The path to the cluster config does not exist: %w.", err)
	}
	y, err := os.ReadFile(path)
	if err != nil {
		return &ApplicationConfig{}, err
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
	setValues, err := parseValues(values)
	if err != nil {
		return &ApplicationConfig{}, err
	}
	// render application dependencies
	for idx, ad := range v.ApplicationDependencies {
		tv[ad.Name] = false
		for _, application := range clusterConfig.Applications {
			if application.Configuration.Repository == ad.Repository {
				v.ApplicationDependencies[idx].Value = true
				delete(tv, ad.Name)
				tv[ad.Name] = true
				// TODO
				// check that the application.Configuration.sha is include in
				// `git rev-parse applicationDependency.shaRange`
			}
		}
	}
	// render user values
	for idx, userValue := range v.UserValues {
		value := setValues[userValue.Name]
		if userValue.Required == true && (value == "" || value == nil) {
			return &ApplicationConfig{}, fmt.Errorf("user value with name '%s' is not set using `--set-value` and is required for the application", userValue.Name)
		}
		v.UserValues[idx].Value = value
		tv[userValue.Name] = value
	}
	// render cluster values
	for idx, clusterValue := range v.ClusterValues {
		// if value is overwrite by the --set-value flag
		if value, ok := setValues[clusterValue.Name]; ok {
			v.ClusterValues[idx].Value = value
			tv[clusterValue.Name] = value
			continue
		}
		t := template.Must(template.New("clusterValue").Funcs(funcMap()).Parse(clusterValue.Template))
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
	// render application values
	for idx, applicationValue := range v.ApplicationValues {
		// if value is overwrite by the --set-value flag
		if value, ok := setValues[applicationValue.Name]; ok {
			v.ApplicationValues[idx].Value = value
			tv[applicationValue.Name] = value
			continue
		}
		var repository Repository
		for _, application := range clusterConfig.Applications {
			if application.Configuration.Repository == applicationValue.Repository {
				repository = application.Repository
			}
		}
		if repository.URL == "" && repository.Name == "" {
			if applicationValue.Required == true {
				return &ApplicationConfig{}, fmt.Errorf("application repository of the application value with name '%s' not found", applicationValue.Name)
			}
			v.ApplicationValues[idx].Value = ""
			tv[applicationValue.Name] = ""
			continue
		}
		applicationCloneOptions := cloneOptions
		applicationCloneOptions.URL = repository.URL
		applicationCloneOptions.Owner = repository.Owner
		applicationCloneOptions.RepositoryName = repository.Name
		applicationCloneOptions.Branch = repository.Branch
		applicationRepo, err := CloneApplicationRepo(applicationCloneOptions, status)
		if err != nil {
			return &ApplicationConfig{}, fmt.Errorf("error in the application value with name %s: %w", applicationValue.Name, err)
		}
		applicationFile, err := OpenApplicationFile(filepath.Join(applicationRepo.git.Path(), applicationValue.Path))
		if err != nil {
			return &ApplicationConfig{}, fmt.Errorf("error in the application value with name %s: %w", applicationValue.Name, err)
		}
		value, err := GetValueFromMap(applicationFile, applicationValue.Keys)
		if err != nil {
			return &ApplicationConfig{}, fmt.Errorf("error in the application value with name %s: %w", applicationValue.Name, err)
		}
		v.ApplicationValues[idx].Value = value
		tv[applicationValue.Name] = value
	}
	// render passwords
	for idx, pwd := range v.Passwords {
		// if value is overwrite by the --set-value flag
		if value, ok := setValues[pwd.Name]; ok {
			v.Passwords[idx].Value = value
			tv[pwd.Name] = value
			continue
		}
		value, err := password.Generate(
			pwd.Lenght,
			pwd.NumDigits,
			pwd.NumSymbols,
			pwd.NoUpper,
			pwd.AllowRepeat,
		)
		if err != nil {
			return &ApplicationConfig{}, fmt.Errorf(
				"error in the password with name %s: %w",
				pwd.Name,
				err,
			)
		}
		if pwd.Base64 == true {
			value = base64.StdEncoding.EncodeToString([]byte(value))
		}
		v.Passwords[idx].Value = value
		tv[pwd.Name] = value
	}
	// render the application configuration (without the values) with the template values
	t = template.Must(template.New("applicationConfig").Funcs(funcMap()).Parse(strings.ReplaceAll(string(y), vy, "")))
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
	if c.Namespace == "" {
		c.Namespace = c.Name
	}
	if c.ServiceAccountName == "" {
		c.ServiceAccountName = c.Name
	}
	// render application secrets
	for idx, applicationSecret := range v.ApplicationSecrets {
		var repository Repository
		for _, application := range clusterConfig.Applications {
			if application.Configuration.Repository == applicationSecret.Repository {
				repository = application.Repository
			}
		}
		if repository.URL == "" && repository.Name == "" {
			v.ApplicationSecrets[idx].Secret = nil
			continue
		}
		applicationCloneOptions := cloneOptions
		applicationCloneOptions.URL = repository.URL
		applicationCloneOptions.Owner = repository.Owner
		applicationCloneOptions.RepositoryName = repository.Name
		applicationCloneOptions.Branch = repository.Branch
		applicationRepo, err := CloneApplicationRepo(applicationCloneOptions, status)
		if err != nil {
			return &ApplicationConfig{}, fmt.Errorf("error in the application secret number %d: %w", idx, err)
		}
		secret, err := OpenApplicationFile(filepath.Join(applicationRepo.git.Path(), applicationSecret.OriginPath))
		if err != nil {
			return &ApplicationConfig{}, fmt.Errorf("error in the application secret number %d: %w", idx, err)
		}
		v.ApplicationSecrets[idx].Secret = secret
	}
	// add the values (removed for rendering) to the config
	c.Values = *v
	return c, nil
}

func (c *ApplicationConfig) Check(clusterConfig *ClusterConfig, alreadyInstalled bool, status *cli.Status) error {
	status.Start("Check that the application can be installed ")
	defer status.End(false)
	if alreadyInstalled == false {
		for _, application := range clusterConfig.Applications {
			if application.Name == c.Name && application.Configuration.Namespace == c.Namespace {
				return fmt.Errorf(
					"another application with the name \"%s\" and the namespace \"%s\" already exists in the cluster. Use the flags `--name=<new-name> --namespace=<new-namespace>` to use another application name and another application namespace",
					c.Name,
					c.Namespace,
				)
			}
			if application.Name == c.Name {
				return fmt.Errorf("another application with the name \"%s\" already exists in the cluster. Use the flag `--name=<new-name>` to use another application name", c.Name)
			}
			if application.Configuration.Namespace == c.Namespace {
				return fmt.Errorf(
					"another application with the namespace \"%s\" already exists in the cluster. Use the flag `--namespace=<new-namespace>` to use another application namespace",
					c.Namespace,
				)
			}
		}
	}
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

func (c *ApplicationConfig) GetUrl() (string, error) {
	if c.TransportType == "" {
		c.TransportType = "ssh"
	}
	url, err := DecodeUniversalURL(c.Repository, c.TransportType)
	if err != nil {
		return "", err
	}
	return url, nil
}

func (c *ApplicationConfig) GetSha() (string, error) {
	return c.Sha, nil
}

func parseValues(values []string) (map[string]interface{}, error) {
	base := map[string]interface{}{}
	for _, value := range values {
		if err := strvals.ParseInto(value, base); err != nil {
			return nil, fmt.Errorf("failed parsing --set-value data: %w", err)
		}
	}
	return base, nil
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

func UniversalURL(URL string) (string, gitprovider.TransportType, error) {
	uURL, err := url.Parse(URL)
	if err != nil {
		return "", gitprovider.TransportType(""), fmt.Errorf("git URL parse failed: %w", err)
	}
	host := uURL.Host
	path := uURL.Path
	if path[len(path)-4:] == ".git" {
		path = path[:len(path)-4]
	}
	return host + path, gitprovider.TransportType(uURL.Scheme), nil
}

func DecodeUniversalURL(URL string, transport gitprovider.TransportType) (string, error) {
	uURL, err := url.Parse(URL)
	if err != nil {
		return "", fmt.Errorf("error during url parsing DecodeUniversalURL: %w", err)
	}
	switch transport {
	case gitprovider.TransportTypeHTTPS:
		uURL.Scheme = "https"
		uURL.Path = uURL.Path + ".git"
		return uURL.String(), nil
	case gitprovider.TransportTypeSSH:
		uURL.Scheme = "ssh"
		uURL.Path = "git@" + uURL.Path
		return uURL.String(), nil
	}
	return "", fmt.Errorf("transport type %s not supported", transport)
}

func CreateRepository(URL, branch, provider, path string) (Repository, error) {
	if provider == "gitlab" || provider == "github" {
		uURL, _, err := UniversalURL(URL)
		if err != nil {
			return Repository{}, fmt.Errorf("git URL parse failed: %w", err)
		}
		elements := strings.Split(uURL, "/")
		owner := elements[1]
		repositoryName := strings.Join(elements[2:], "/")
		return Repository{
			URL:    "",
			Owner:  owner,
			Name:   repositoryName,
			Branch: branch,
			Path:   path,
		}, nil
	} else {
		uURL, err := url.Parse("https://" + URL)
		if err != nil {
			return Repository{}, fmt.Errorf("git URL parse failed: %w", err)
		}
		return Repository{
			URL:    uURL.String(),
			Owner:  "",
			Name:   "",
			Branch: branch,
			Path:   path,
		}, nil
	}

}
