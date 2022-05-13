package repo

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

type Repository struct {
	URL    string `json:"url,omitempty"`
	Owner  string `json:"owner,omitempty"`
	Name   string `json:"name,omitempty"`
	Branch string `json:"branch,omitempty"`
}

type Application struct {
	Name          string            `json:"name"`
	Repository    Repository        `json:"repository"`
	Configuration ApplicationConfig `json:"configuration"`
}

type Configuration struct {
	Repository string `json:"repository"`
	Sha        string `json:"sha"`
}

type ClusterConfig struct {
	Repository    string                 `json:"repository"`
	Sha           string                 `json:"sha"`
	AgeKey        string                 `json:"ageKey,omitempty"`
	SopsAgeSecret string                 `json:"sopsAgeSecret,omitempty"`
	Applications  []Application          `json:"applications,omitempty"`
	Env           map[string]interface{} `json:"env,omitempty"`
}

func NewClusterConfig(repository string, sha string) *ClusterConfig {
	return &ClusterConfig{
		Repository:    repository,
		Sha:           sha,
		AgeKey:        "",
		SopsAgeSecret: "",
		Applications:  []Application{},
	}
}

func OpenClusterConfig(path string) (*ClusterConfig, error) {
	_, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("the path to the cluster config does not exist: %w.", err)
	}
	y, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &ClusterConfig{}
	err = yaml.Unmarshal([]byte(y), &c)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *ClusterConfig) Save(path string) error {
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
		f.Close()
		return fmt.Errorf("cluster config file saved but empty.")
	}
	err = f.Close()
	if err != nil {
		return err
	}
	return nil
}

func (c *ClusterConfig) AddApplication(repository Repository, applicationConfig *ApplicationConfig) {
	c.Applications = appendApplicationIfMissing(c.Applications, Application{
		Name:          applicationConfig.Name,
		Repository:    repository,
		Configuration: *applicationConfig,
	})
}

func (c *ClusterConfig) RemoveApplication(name string) {
	c.Applications = removeApplicationByName(c.Applications, name)
}

func (c *ClusterConfig) AddEnv(name, value string) {
	if c.Env == nil {
		c.Env = make(map[string]interface{})
	}
	c.Env[name] = value
}

func appendApplicationIfMissing(slice []Application, elem Application) []Application {
	for _, ele := range slice {
		if ele.Repository == elem.Repository && ele.Name == ele.Name {
			return slice
		}
	}
	return append(slice, elem)
}

func removeApplicationByName(slice []Application, name string) []Application {
	for idx, app := range slice {
		if app.Name == name {
			slice[idx] = slice[len(slice)-1]
			return slice[:len(slice)-1]
		}
	}
	return slice
}
