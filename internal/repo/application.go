package repo

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sethvargo/go-password/password"
	"gitlab.com/openlizz/lizz/internal/config"
	"gitlab.com/openlizz/lizz/internal/git/gogit"
	"gitlab.com/openlizz/lizz/internal/logger/cli"
	"gitlab.com/openlizz/lizz/internal/yaml"
	"go.mozilla.org/sops/cmd/sops/codes"
	"go.mozilla.org/sops/v3/cmd/sops/common"
)

type ApplicationRepo struct {
	config *config.ApplicationConfig
	git    *gogit.GoGit
}

func CloneApplicationRepo(options *CloneOptions, status *cli.Status) (*ApplicationRepo, error) {
	status.Start("Clone the application repository ")
	defer status.End(false)
	git, err := Clone(options)
	if err != nil {
		return nil, err
	}
	status.End(true)
	return &ApplicationRepo{
		config: &config.ApplicationConfig{},
		git:    git,
	}, nil
}

func (r *ApplicationRepo) Config() *config.ApplicationConfig {
	return r.config
}

func (r *ApplicationRepo) Git() *gogit.GoGit {
	return r.git
}

func (r *ApplicationRepo) OpenApplicationConfig() error {
	c, err := config.OpenApplicationConfig(filepath.Join(r.git.Path(), "config.yaml"))
	if err != nil {
		return err
	}
	r.config = c
	return nil
}

func (r *ApplicationRepo) RenderApplicationConfig(clusterConfig *config.ClusterConfig, status *cli.Status) error {
	status.Start("Render the application configuration ")
	defer status.End(false)
	c, err := config.RenderApplicationConfig(
		filepath.Join(r.git.Path(), "config.yaml"),
		clusterConfig,
	)
	if err != nil {
		return err
	}
	r.config = c
	status.End(true)
	return nil
}

func (r *ApplicationRepo) CommitPush(
	authorName string,
	authorEmail string,
	message string,
	destinationUrl string,
	timeout time.Duration,
	status *cli.Status,
) error {
	status.Start("Commit and push to the application repository ")
	defer status.End(false)
	err := CommitPush(r.git, authorName, authorEmail, message, destinationUrl, timeout)
	if err != nil {
		return err
	}
	status.End(true)
	return nil
}

func (r *ApplicationRepo) Render(status *cli.Status) error {
	status.Start("Render the application values ")
	defer status.End(false)
	tv := make(map[string]interface{})
	for _, v := range r.config.Values.ApplicationDependencies {
		tv[v.Name] = v.Value
	}
	for _, v := range r.config.Values.ApplicationValues {
		tv[v.Name] = v.Value
	}
	for _, v := range r.config.Values.ClusterValues {
		tv[v.Name] = v.Value
	}
	for _, pwd := range r.config.Values.Passwords {
		res, err := password.Generate(
			pwd.Lenght,
			pwd.NumDigits,
			pwd.NumSymbols,
			pwd.NoUpper,
			pwd.AllowRepeat,
		)
		if err != nil {
			return err
		}
		tv[pwd.Name] = res
	}
	var fps []string
	err := filepath.Walk(r.git.Path(), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() == false && strings.Index(path, ".git") == -1 {
			blackListed := false
			for _, blackListedPath := range append(r.config.TemplatingBlackList, "config.yaml") {
				backListedInfo, err := os.Stat(filepath.Join(r.git.Path(), blackListedPath))
				if err != nil {
					return err
				}
				if os.SameFile(backListedInfo, info) {
					blackListed = true
				}
			}
			if blackListed == false {
				fps = append(fps, path)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, path := range fps {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		t := template.Must(template.New("applicationFile").Parse(string(data)))
		var tpl bytes.Buffer
		err = t.Execute(&tpl, tv)
		if err != nil {
			return fmt.Errorf("error while rendering the application configuration file: %w", err)
		}
		file, err := os.Create(path)
		if err != nil {
			return common.NewExitError(
				fmt.Sprintf("could not open in-place file for writing: %s", err),
				codes.CouldNotWriteOutputFile,
			)
		}
		defer file.Close()
		_, err = file.Write(tpl.Bytes())
		if err != nil {
			return err
		}
	}
	status.End(true)
	return nil
}

func (r *ApplicationRepo) Encrypt(clusterConfig *config.ClusterConfig, status *cli.Status) error {
	status.Start("Encrypt the application files ")
	defer status.End(false)
	if r.config.Encryption.Enabled == true {
		for _, inputPath := range r.config.Encryption.InputPaths {
			yamlE, err := yaml.EncryptYaml(
				filepath.Join(r.git.Path(), inputPath),
				clusterConfig.AgeKey,
			)
			if err != nil {
				return err
			}
			err = yaml.Save(yamlE, filepath.Join(r.git.Path(), inputPath))
			if err != nil {
				return err
			}
		}
	}
	status.End(true)
	return nil
}
