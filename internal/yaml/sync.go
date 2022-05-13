package yaml

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1beta2"
	"github.com/fluxcd/pkg/apis/meta"
	sourcev1 "github.com/fluxcd/source-controller/api/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

func NewSyncYaml(
	namespace string,
	name string,
	URL string,
	branch string,
	decryption bool,
	decryptionSecret string,
	dependsOn []meta.NamespacedObjectReference,
	serviceAccountName string,
	sourceSecret bool,
	sourceSecretName string,
) (string, error) {
	uURL, err := url.Parse(URL)
	if err != nil {
		return "", fmt.Errorf("git URL parse failed: %w", err)
	}
	if uURL.Scheme != "http" && uURL.Scheme != "https" && uURL.Scheme != "ssh" {
		return "", fmt.Errorf(
			"git URL scheme '%s' not supported, can be: http, https, or ssh",
			uURL.Scheme,
		)
	}
	var secretRef *meta.LocalObjectReference
	if sourceSecret == true {
		secretRef = &meta.LocalObjectReference{Name: sourceSecretName}
	} else {
		secretRef = nil
		if uURL.Scheme == "ssh" {
			// if no secret specified then use https instead of ssh
			URL = "https://" + uURL.Host + uURL.Path
		}
	}
	gitRepositoryC := sourcev1.GitRepository{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: sourcev1.GitRepositorySpec{
			Interval: metav1.Duration{
				Duration: 5 * time.Minute,
			},
			URL:       URL,
			Reference: &sourcev1.GitRepositoryRef{Branch: branch},
			SecretRef: secretRef,
		},
	}
	var decryptionC *kustomizev1.Decryption
	if decryption == true {
		decryptionC = &kustomizev1.Decryption{
			Provider:  "sops",
			SecretRef: &meta.LocalObjectReference{Name: decryptionSecret},
		}
	}
	kustomizationC := kustomizev1.Kustomization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: kustomizev1.KustomizationSpec{
			ServiceAccountName: serviceAccountName,
			DependsOn:          dependsOn,
			Interval: metav1.Duration{
				Duration: 5 * time.Minute,
			},
			Prune: true,
			SourceRef: kustomizev1.CrossNamespaceSourceReference{
				Kind: "GitRepository",
				Name: name,
			},
			Validation: "client",
			Decryption: decryptionC,
		},
	}
	syncY, err := exportRepository(gitRepositoryC, kustomizationC)
	if err != nil {
		return "", err
	}
	return syncY, nil
}

func exportRepository(
	gitRepository sourcev1.GitRepository,
	kustomization kustomizev1.Kustomization,
) (string, error) {
	var builder strings.Builder
	gitRepository.TypeMeta = metav1.TypeMeta{
		APIVersion: "source.toolkit.fluxcd.io/v1beta1",
		Kind:       "GitRepository",
	}
	data, err := yaml.Marshal(gitRepository)
	if err != nil {
		return "", err
	}
	builder.WriteString(resourceToString(data))
	kustomization.TypeMeta = metav1.TypeMeta{
		APIVersion: "kustomize.toolkit.fluxcd.io/v1beta2",
		Kind:       "Kustomization",
	}
	data, err = yaml.Marshal(kustomization)
	if err != nil {
		return "", err
	}
	builder.WriteString("---\n")
	builder.WriteString(resourceToString(data))
	return builder.String(), nil
}
