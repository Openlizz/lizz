package repo

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	ignore "github.com/sabhiram/go-gitignore"
	"github.com/sethvargo/go-password/password"
	"gitlab.com/openlizz/lizz/internal/git/gogit"
	"gitlab.com/openlizz/lizz/internal/logger/cli"
	"gitlab.com/openlizz/lizz/internal/yaml"
	"go.mozilla.org/sops/cmd/sops/codes"
	"go.mozilla.org/sops/v3/cmd/sops/common"
	yaml2 "gopkg.in/yaml.v2"
)

type ApplicationRepo struct {
	config *ApplicationConfig
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
		config: &ApplicationConfig{},
		git:    git,
	}, nil
}

func (r *ApplicationRepo) Config() *ApplicationConfig {
	return r.config
}

func (r *ApplicationRepo) Git() *gogit.GoGit {
	return r.git
}

func (r *ApplicationRepo) OpenApplicationConfig() error {
	c, err := OpenApplicationConfig(filepath.Join(r.git.Path(), "config.yaml"))
	if err != nil {
		return err
	}
	r.config = c
	return nil
}

func (r *ApplicationRepo) RenderApplicationConfig(clusterConfig *ClusterConfig, cloneOptions *CloneOptions, status *cli.Status) error {
	status.Start("Render the application configuration ")
	defer status.End(false)
	c, err := RenderApplicationConfig(
		filepath.Join(r.git.Path(), "config.yaml"),
		clusterConfig,
		cloneOptions,
		status,
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
	destinationBranch string,
	timeout time.Duration,
	status *cli.Status,
) error {
	status.Start("Commit and push to the application repository ")
	defer status.End(false)
	err := CommitPush(r.git, authorName, authorEmail, message, destinationUrl, destinationBranch, timeout)
	if err != nil {
		return err
	}
	status.End(true)
	return nil
}

func (r *ApplicationRepo) Render(destinationRepo *Repository, username, pwd string, status *cli.Status) error {
	status.Start("Render the application values ")
	defer status.End(false)
	tv := make(map[string]interface{})
	tv["name"] = r.config.Name
	tv["namespace"] = r.config.Namespace
	tv["serviceAccountName"] = r.config.ServiceAccountName
	tv["repository"] = destinationRepo
	tv["username"] = username
	tv["password"] = pwd
	for _, v := range r.config.Values.ApplicationDependencies {
		for k := range tv {
			if v.Name == k {
				return fmt.Errorf("application value name already taken. '%s' already has the value: '%s'. Please use another name.", k, tv[k])
			}
		}
		tv[v.Name] = v.Value
		if v.Print == true {
			status.PrintValue(v.Name, v.Description, tv[v.Name])
		}
	}
	for _, v := range r.config.Values.ApplicationValues {
		for k := range tv {
			if v.Name == k {
				return fmt.Errorf("application value name already taken. '%s' already has the value: '%s'. Please use another name.", k, tv[k])
			}
		}
		tv[v.Name] = v.Value
	}
	for _, v := range r.config.Values.ClusterValues {
		for k := range tv {
			if v.Name == k {
				return fmt.Errorf("application value name already taken. '%s' already has the value: '%s'. Please use another name.", k, tv[k])
			}
		}
		tv[v.Name] = v.Value
		if v.Print == true {
			status.PrintValue(v.Name, v.Description, tv[v.Name])
		}
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
		if pwd.Print == true {
			status.PrintValue(pwd.Name, pwd.Description, res)
		}
		if pwd.Base64 == true {
			res = base64.StdEncoding.EncodeToString([]byte(res))
		}
		for k := range tv {
			if pwd.Name == k {
				return fmt.Errorf("application value name already taken. '%s' already has the value: '%s'. Please use another name.", k, tv[k])
			}
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
			object := ignore.CompileIgnoreLines(append(r.config.TemplatingBlackList, "config.yaml")...)
			blackListed = object.MatchesPath(strings.Replace(path, r.git.Path()+"/", "", -1))
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
		t = template.Must(template.New("applicationFile").Funcs(funcMap()).Parse(string(data)))
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
	for _, v := range r.config.Values.ApplicationSecrets {
		v.Secret["metadata"].(map[interface{}]interface{})["namespace"] = r.config.Namespace
		y, err := yaml2.Marshal(v.Secret)
		if err != nil {
			return err
		}
		err = yaml.Save(string(y), filepath.Join(r.git.Path(), v.DestinationPath))
		if err != nil {
			return fmt.Errorf("error while saving the application secret: %w", err)
		}
		r.config.Encryption.Enabled = true
		ky, err := yaml.Read(filepath.Join(r.git.Path(), v.KustomizationPath))
		if err != nil {
			return fmt.Errorf("error while reading the kustomization file of the application secret: %w", err)
		}
		k, err := yaml.ReadKustomization(ky)
		if err != nil {
			return fmt.Errorf("error while reading kustomization of the kustomization file of the application secret: %w", err)
		}
		rel, err := filepath.Rel(path.Dir(v.KustomizationPath), v.DestinationPath)
		if err != nil {
			return fmt.Errorf("error while getting the resource relative path for the application secret: %w", err)
		}
		k.Resources = append(k.Resources, rel)
		ky, err = yaml.ExportKustomization(k)
		if err != nil {
			return fmt.Errorf("error while exporting the kustomization for the application secret: %w", err)
		}
		err = yaml.Save(ky, filepath.Join(r.git.Path(), v.KustomizationPath))
		if err != nil {
			return fmt.Errorf("error while saving the kustomization file of the application secret: %w", err)
		}
	}
	status.End(true)
	return nil
}

func (r *ApplicationRepo) Encrypt(clusterConfig *ClusterConfig, status *cli.Status) error {
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
