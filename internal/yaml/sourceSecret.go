package yaml

import (
	"crypto/elliptic"
	"fmt"
	"net/url"

	"github.com/fluxcd/flux2/pkg/manifestgen/sourcesecret"
	"gitlab.com/openlizz/lizz/internal/flags"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

func NewSourceSecretYaml(
	namespace string,
	name string,
	username string,
	password string,
	tokenAuth bool,
	caFile string,
	repositoryURL *url.URL,
	keyAlgorithm flags.PublicKeyAlgorithm,
	keyRSABits flags.RSAKeyBits,
	keyECDSACurve flags.ECDSACurve,
	sshHostname string,
	privateKeyFile string,
) (string, string, error) {
	secretOpts := sourcesecret.Options{
		Name:         name,
		Namespace:    namespace,
		ManifestFile: sourcesecret.MakeDefaultOptions().ManifestFile,
	}
	if tokenAuth {
		secretOpts.Username = username
		secretOpts.Password = password

		if caFile != "" {
			secretOpts.CAFilePath = caFile
		}

		// Remove port of the given host when not syncing over HTTP/S to not assume port for protocol
		// This _might_ be overwritten later on by e.g. --ssh-hostname
		if repositoryURL.Scheme != "https" && repositoryURL.Scheme != "http" {
			repositoryURL.Host = repositoryURL.Hostname()
		}

		// Configure repository URL to match auth config for sync.
		repositoryURL.User = nil
		repositoryURL.Scheme = "https"
	} else {
		if keyAlgorithm == "" {
			keyAlgorithm = flags.PublicKeyAlgorithm(sourcesecret.ECDSAPrivateKeyAlgorithm)
		}
		if keyRSABits == 0 {
			keyRSABits = 2048
		}
		keyECDSACurveNil := flags.ECDSACurve{Curve: nil}
		if keyECDSACurve == keyECDSACurveNil {
			keyECDSACurve = flags.ECDSACurve{Curve: elliptic.P384()}
		}
		secretOpts.PrivateKeyAlgorithm = sourcesecret.PrivateKeyAlgorithm(keyAlgorithm)
		secretOpts.Password = password
		secretOpts.RSAKeyBits = int(keyRSABits)
		secretOpts.ECDSACurve = keyECDSACurve.Curve

		// Configure repository URL to match auth config for sync

		// Override existing user when user is not already set
		// or when a username was passed in
		if repositoryURL.User == nil || username != "git" {
			repositoryURL.User = url.User(username)
		}

		repositoryURL.Scheme = "ssh"
		if sshHostname != "" {
			repositoryURL.Host = sshHostname
		}
		if privateKeyFile != "" {
			secretOpts.PrivateKeyPath = privateKeyFile
		}

		// Configure last as it depends on the config above.
		secretOpts.SSHHostname = repositoryURL.Host

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
