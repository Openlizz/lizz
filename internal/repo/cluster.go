package repo

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openlizz/lizz/internal/git/gogit"
	"github.com/openlizz/lizz/internal/logger/cli"
	"github.com/openlizz/lizz/internal/yaml"
	yml "sigs.k8s.io/yaml"
)

type ClusterRepo struct {
	config *ClusterConfig
	git    *gogit.GoGit
}

func CloneClusterRepo(options *CloneOptions, status *cli.Status) (*ClusterRepo, error) {
	status.Start("Clone the cluster repository ")
	defer status.End(false)
	git, err := Clone(options)
	if err != nil {
		return nil, err
	}
	status.End(true)
	return &ClusterRepo{
		config: &ClusterConfig{},
		git:    git,
	}, nil
}

func (r *ClusterRepo) Config() *ClusterConfig {
	return r.config
}

func (r *ClusterRepo) Git() *gogit.GoGit {
	return r.git
}

func (r *ClusterRepo) NewClusterConfig(repository string, sha string, status *cli.Status) error {
	status.Start("Create a new configuration for the cluster")
	defer status.End(false)
	c := NewClusterConfig(repository, sha)
	r.config = c
	err := r.SaveClusterConfig()
	if err != nil {
		return err
	}
	status.End(true)
	return nil
}

func (r *ClusterRepo) OpenClusterConfig(status *cli.Status) error {
	status.Start("Open and read the cluster configuration file")
	defer status.End(false)
	c, err := OpenClusterConfig(filepath.Join(r.git.Path(), configFilename))
	if err != nil {
		return err
	}
	r.config = c
	err = r.SaveClusterConfig()
	if err != nil {
		return err
	}
	status.End(true)
	return nil
}

func (r *ClusterRepo) SaveClusterConfig() error {
	cY, err := yml.Marshal(r.config)
	if err != nil {
		return err
	}
	err = yaml.Save(string(cY), filepath.Join(r.git.Path(), configFilename))
	if err != nil {
		return err
	}
	return nil
}

func (r *ClusterRepo) ConfigureSecretManagement(secretName string, output string, path string, status *cli.Status) error {
	status.Start("Configure the secret management")
	defer status.End(false)
	secretY, k, err := yaml.NewSecretSopsYaml(secretName)
	if err != nil {
		return err
	}
	err = yaml.Save(secretY, output)
	if err != nil {
		return err
	}
	yamlE, err := yaml.EncryptYaml(output, k.Recipient().String())
	if err != nil {
		return err
	}
	if r.config.AgeKey != "" || r.config.SopsAgeSecret != "" {
		return fmt.Errorf("the cluster already has an age key configured")
	}
	r.config.AgeKey = k.Recipient().String()
	r.config.SopsAgeSecret = string(yamlE)
	err = r.config.Save(filepath.Join(r.git.Path(), configFilename))
	if err != nil {
		return err
	}
	clusterApplicationsY, err := yaml.DecryptionClusterApplicationsYaml(
		filepath.Join(r.git.Path(), path),
		secretName,
	)
	if err != nil {
		return err
	}
	err = yaml.Save(clusterApplicationsY, filepath.Join(r.git.Path(), path))
	if err != nil {
		return err
	}
	status.End(true)
	return nil
}

func (r *ClusterRepo) AddApplication(
	URL string,
	branch string,
	provider string,
	destinationPrivate bool,
	applicationConfig *ApplicationConfig,
	clusterRole bool,
	decryptionSecret string,
	path string,
	sourceSecretOptions *yaml.SourceSecretOptions,
	status *cli.Status,
) (string, error) {
	status.Start("Add the application to the cluster repository ")
	defer status.End(false)
	repository, err := CreateRepository(URL, branch, provider, path)
	if err != nil {
		return "", err
	}
	r.config.AddApplication(repository, applicationConfig)
	err = r.config.Save(filepath.Join(r.git.Path(), configFilename))
	if err != nil {
		return "", err
	}
	rbacY, err := yaml.NewRbacYaml(applicationConfig.Namespace, applicationConfig.Name, "cluster-admin", clusterRole, applicationConfig.ServiceAccountName)
	if err != nil {
		return "", err
	}
	err = yaml.Save(
		rbacY,
		filepath.Join(r.Git().Path(), "applications", "base", applicationConfig.Name, "rbac.yaml"),
	)
	if err != nil {
		return "", err
	}
	repositoryURL, err := url.Parse(URL)
	if err != nil {
		return "", err
	}
	var publicKey string
	// Create secret for git repo credentials and pass the name of the secret to sync
	if destinationPrivate == true {
		var sourceSecretY string
		sourceSecretY, publicKey, err = yaml.NewSourceSecretYaml(repositoryURL, sourceSecretOptions)
		if err != nil {
			return "", err
		}
		err = yaml.Save(
			sourceSecretY,
			filepath.Join(
				r.Git().Path(),
				"applications",
				"base",
				applicationConfig.Name,
				"sourcesecret.yaml",
			),
		)
		if err != nil {
			return "", err
		}
		sourceSecretEncryptedY, err := yaml.EncryptYaml(filepath.Join(
			r.Git().Path(),
			"applications",
			"base",
			applicationConfig.Name,
			"sourcesecret.yaml",
		), r.config.AgeKey)
		if err != nil {
			return "", err
		}
		err = yaml.Save(
			sourceSecretEncryptedY,
			filepath.Join(
				r.Git().Path(),
				"applications",
				"base",
				applicationConfig.Name,
				"sourcesecret.yaml",
			),
		)
		if err != nil {
			return "", err
		}
	}
	syncY, err := yaml.NewSyncYaml(
		applicationConfig.Namespace,
		applicationConfig.Name,
		repositoryURL.String(),
		branch,
		applicationConfig.Encryption.Enabled || destinationPrivate,
		decryptionSecret,
		applicationConfig.DependsOn,
		applicationConfig.ServiceAccountName,
		destinationPrivate,
		sourceSecretOptions.Name,
	)
	if err != nil {
		return "", err
	}
	err = yaml.Save(
		syncY,
		filepath.Join(r.Git().Path(), "applications", "base", applicationConfig.Name, "sync.yaml"),
	)
	if err != nil {
		return "", err
	}
	if applicationConfig.Encryption.Enabled == true || destinationPrivate == true {
		err = yaml.Save(
			strings.Replace(
				r.Config().SopsAgeSecret,
				"namespace: flux-system",
				"namespace: "+applicationConfig.Namespace,
				1,
			),
			filepath.Join(
				r.Git().Path(),
				"applications",
				"base",
				applicationConfig.Name,
				"secret.yaml",
			),
		)
		if err != nil {
			return "", err
		}
	}
	kustomizeY, err := yaml.NewKustomizationYaml(
		applicationConfig.Encryption.Enabled || destinationPrivate,
		destinationPrivate,
	)
	if err != nil {
		return "", err
	}
	err = yaml.Save(
		kustomizeY,
		filepath.Join(
			r.Git().Path(),
			"applications",
			"base",
			applicationConfig.Name,
			"kustomization.yaml",
		),
	)
	if err != nil {
		return "", err
	}
	patchY, err := yaml.NewPatchYaml(
		applicationConfig.Namespace,
		applicationConfig.Name,
		path,
	)
	if err != nil {
		return "", err
	}
	err = yaml.Save(
		patchY,
		filepath.Join(r.Git().Path(), "applications", applicationConfig.Name+"-patch.yaml"),
	)
	if err != nil {
		return "", err
	}
	applicationsY, err := yaml.AddApplicationsYaml(
		filepath.Join(r.Git().Path(), "applications", "kustomization.yaml"),
		applicationConfig.Name,
	)
	if err != nil {
		return "", err
	}
	err = yaml.Save(
		applicationsY,
		filepath.Join(r.Git().Path(), "applications", "kustomization.yaml"),
	)
	if err != nil {
		return "", err
	}
	status.End(true)
	return publicKey, nil
}

func (r *ClusterRepo) RemoveApplication(name string, status *cli.Status) error {
	status.Start("Remove the application from the cluster")
	defer status.End(false)
	r.config.RemoveApplication(name)
	err := r.config.Save(filepath.Join(r.git.Path(), configFilename))
	if err != nil {
		return err
	}
	pathApplication := filepath.Join(r.git.Path(), "applications", "base", name)
	if _, err := os.Stat(pathApplication); err == nil {
		err = os.RemoveAll(pathApplication)
		if err != nil {
			return err
		}
	} else if errors.Is(err, os.ErrNotExist) {
	} else {
		return err

	}
	pathPatch := filepath.Join(r.git.Path(), "applications", name+"-patch.yaml")
	if _, err := os.Stat(pathPatch); err == nil {
		err = os.RemoveAll(pathPatch)
		if err != nil {
			return err
		}
	} else if errors.Is(err, os.ErrNotExist) {
	} else {
		return err

	}
	applicationsY, err := yaml.RemoveApplicationsYaml(
		filepath.Join(r.Git().Path(), "applications", "kustomization.yaml"),
		name,
	)
	if err != nil {
		return err
	}
	err = yaml.Save(
		applicationsY,
		filepath.Join(r.Git().Path(), "applications", "kustomization.yaml"),
	)
	if err != nil {
		return err
	}
	status.End(true)
	return nil
}

func (r *ClusterRepo) RefreshApplication(name string, applicationConfig *ApplicationConfig, status *cli.Status) error {
	status.Start("Refresh the application from the cluster")
	defer status.End(false)
	path := ""
	for _, application := range r.config.Applications {
		if application.Name == name {
			application.Configuration.Sha = applicationConfig.Sha
			path = application.Repository.Path
		}
	}
	if path == "" {
		return fmt.Errorf("application %s not found in cluster repository configuration", name)
	}
	// Update dependsOn value of sync.yaml
	syncY, err := yaml.Read(filepath.Join(r.Git().Path(), "applications", "base", applicationConfig.Name, "sync.yaml"))
	if err != nil {
		return err
	}
	syncY, err = yaml.UpdateDependsOnSyncYaml(syncY, applicationConfig.DependsOn)
	if err != nil {
		return err
	}
	err = yaml.Save(
		syncY,
		filepath.Join(r.Git().Path(), "applications", "base", applicationConfig.Name, "sync.yaml"),
	)
	if err != nil {
		return err
	}
	// Update path value of <application name>-patch.yaml
	patchY, err := yaml.Read(filepath.Join(r.Git().Path(), "applications", name+"-patch.yaml"))
	if err != nil {
		return err
	}
	patchY, err = yaml.UpdatePathPatchYaml(patchY, path)
	if err != nil {
		return err
	}
	err = yaml.Save(
		patchY,
		filepath.Join(r.Git().Path(), "applications", name+"-patch.yaml"),
	)
	if err != nil {
		return err
	}
	status.End(true)
	return nil
}

func (r *ClusterRepo) CommitPush(
	authorName string,
	authorEmail string,
	message string,
	destinationUrl string,
	destinationBranch string,
	timeout time.Duration,
	status *cli.Status,
) error {
	status.Start("Commit and push to the cluster repository ")
	defer status.End(false)
	err := CommitPush(r.git, authorName, authorEmail, message, destinationUrl, destinationBranch, timeout)
	if err != nil {
		return err
	}
	status.End(true)
	return nil
}
