package repo

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gitlab.com/openlizz/lizz/internal/config"
	"gitlab.com/openlizz/lizz/internal/flags"
	"gitlab.com/openlizz/lizz/internal/git/gogit"
	"gitlab.com/openlizz/lizz/internal/yaml"
	yml "sigs.k8s.io/yaml"
)

type ClusterRepo struct {
	config *config.ClusterConfig
	git    *gogit.GoGit
}

func CloneClusterRepo(URL string, branch string, username string, password string, privateKeyFile string, timeout time.Duration) (*ClusterRepo, error) {
	git, err := Clone(URL, branch, username, password, privateKeyFile, timeout)
	if err != nil {
		return nil, err
	}
	return &ClusterRepo{
		config: &config.ClusterConfig{},
		git:    git,
	}, nil
}

func (r *ClusterRepo) Config() *config.ClusterConfig {
	return r.config
}

func (r *ClusterRepo) Git() *gogit.GoGit {
	return r.git
}

func (r *ClusterRepo) NewClusterConfig(repository string, sha string) error {
	c := config.NewClusterConfig(repository, sha)
	r.config = c
	return r.SaveClusterConfig()
}

func (r *ClusterRepo) OpenClusterConfig() error {
	c, err := config.OpenClusterConfig(filepath.Join(r.git.Path(), "config.yaml"))
	if err != nil {
		return err
	}
	r.config = c
	return r.SaveClusterConfig()
}

func (r *ClusterRepo) SaveClusterConfig() error {
	cY, err := yml.Marshal(r.config)
	if err != nil {
		return err
	}
	err = yaml.Save(string(cY), filepath.Join(r.git.Path(), "config.yaml"))
	if err != nil {
		return err
	}
	return nil
}

func (r *ClusterRepo) ConfigureSecretManagement(secretName string, output string, path string) error {
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
	err = r.config.Save(filepath.Join(r.git.Path(), "config.yaml"))
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
	return nil
}

func (r *ClusterRepo) AddApplication(
	repository string,
	destinationPrivate bool,
	applicationConfig *config.ApplicationConfig,
	clusterRole bool,
	URL string,
	decryptionSecret string,
	path string,
	sourceSecretName string,
	username string,
	password string,
	tokenAuth bool,
	caFile string,
	keyAlgorithm flags.PublicKeyAlgorithm,
	keyRSABits flags.RSAKeyBits,
	keyECDSACurve flags.ECDSACurve,
	sshHostname string,
	privateKeyFile string,
) (string, error) {
	repository, err := config.UniversalURL(repository)
	if err != nil {
		return "", err
	}
	r.config.AddApplication(repository, applicationConfig)
	err = r.config.Save(filepath.Join(r.git.Path(), "config.yaml"))
	if err != nil {
		return "", err
	}
	var serviceAccountName string
	if applicationConfig.ServiceAccountName != "" {
		serviceAccountName = applicationConfig.ServiceAccountName
	} else {
		serviceAccountName = applicationConfig.Name
	}
	rbacY, err := yaml.NewRbacYaml(applicationConfig.Name, applicationConfig.Name, "cluster-admin", clusterRole, serviceAccountName)
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
		sourceSecretY, publicKey, err = yaml.NewSourceSecretYaml(
			applicationConfig.Name,
			sourceSecretName,
			username,
			password,
			tokenAuth,
			caFile,
			repositoryURL,
			keyAlgorithm,
			keyRSABits,
			keyECDSACurve,
			sshHostname,
			privateKeyFile,
		)
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
		applicationConfig.Name,
		applicationConfig.Name,
		repositoryURL.String(),
		applicationConfig.Encryption.Enabled || destinationPrivate,
		decryptionSecret,
		applicationConfig.DependsOn,
		serviceAccountName,
		destinationPrivate,
		sourceSecretName,
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
				"namespace: "+applicationConfig.Name,
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
		applicationConfig.Name,
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
	return publicKey, nil
}

func (r *ClusterRepo) RemoveApplication(name string) error {
	r.config.RemoveApplication(name)
	err := r.config.Save(filepath.Join(r.git.Path(), "config.yaml"))
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
	return nil
}

func (r *ClusterRepo) CommitPush(
	authorName string,
	authorEmail string,
	message string,
	destinationUrl string,
	timeout time.Duration,
) error {
	return CommitPush(r.git, authorName, authorEmail, message, destinationUrl, timeout)
}
