package yaml

import (
	"crypto/elliptic"
	"fmt"
	"net/url"

	"github.com/fluxcd/flux2/pkg/manifestgen/sourcesecret"
	"github.com/openlizz/lizz/internal/flags"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

type SourceSecretOptions struct {
	Namespace      string
	Name           string
	Username       string
	Password       string
	TokenAuth      bool
	CaFile         string
	KeyAlgorithm   flags.PublicKeyAlgorithm
	KeyRSABits     flags.RSAKeyBits
	KeyECDSACurve  flags.ECDSACurve
	Hostname       string
	SshHostname    string
	PrivateKeyFile string
	PlainProvider  bool
}

func NewSourceSecretYaml(repositoryURL *url.URL, options *SourceSecretOptions) (string, string, error) {
	secretOpts := sourcesecret.Options{
		Name:         options.Name,
		Namespace:    options.Namespace,
		ManifestFile: sourcesecret.MakeDefaultOptions().ManifestFile,
	}
	if options.TokenAuth {
		secretOpts.Username = options.Username
		secretOpts.Password = options.Password

		if options.CaFile != "" {
			secretOpts.CAFilePath = options.CaFile
		}
		// Remove port of the given host when not syncing over HTTP/S to not assume port for protocol
		// This _might_ be overwritten later on by e.g. --ssh-hostname
		if repositoryURL.Scheme != "https" && repositoryURL.Scheme != "http" {
			repositoryURL.Host = repositoryURL.Hostname()
		}
		repositoryURL.User = nil
		repositoryURL.Scheme = "https"
	} else {
		if options.KeyAlgorithm == "" {
			options.KeyAlgorithm = flags.PublicKeyAlgorithm(sourcesecret.ECDSAPrivateKeyAlgorithm)
		}
		if options.KeyRSABits == 0 {
			options.KeyRSABits = 2048
		}
		keyECDSACurveNil := flags.ECDSACurve{Curve: nil}
		if options.KeyECDSACurve == keyECDSACurveNil {
			options.KeyECDSACurve = flags.ECDSACurve{Curve: elliptic.P384()}
		}
		secretOpts.PrivateKeyAlgorithm = sourcesecret.PrivateKeyAlgorithm(options.KeyAlgorithm)
		secretOpts.RSAKeyBits = int(options.KeyRSABits)
		secretOpts.ECDSACurve = options.KeyECDSACurve.Curve
		repositoryURL.Scheme = "ssh"
		if options.SshHostname != "" {
			repositoryURL.Host = options.SshHostname
		}
		if options.PrivateKeyFile != "" {
			secretOpts.PrivateKeyPath = options.PrivateKeyFile
		}
		if repositoryURL.User == nil || options.Username != "git" {
			repositoryURL.User = url.User(options.Username)
		}
		if options.PlainProvider == true {
			secretOpts.Password = options.Password
			secretOpts.SSHHostname = repositoryURL.Host
		} else {
			secretOpts.SSHHostname = options.Hostname
		}

	}
	manifest, err := sourcesecret.Generate(secretOpts)
	if err != nil {
		return "", "", err
	}
	var secret corev1.Secret
	if err := yaml.Unmarshal([]byte(manifest.Content), &secret); err != nil {
		return "", "", fmt.Errorf("failed to unmarshal generated source secret manifest: %w", err)
	}
	ppk, ok := secret.StringData[sourcesecret.PublicKeySecretKey]
	if !ok {
		return "", "", fmt.Errorf("error while getting the public key from the source secret")
	}
	return manifest.Content, ppk, nil
}
