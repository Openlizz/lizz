package yaml

import (
	"fmt"
	"os"

	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1beta2"
	"github.com/fluxcd/pkg/apis/meta"
	"sigs.k8s.io/yaml"
)

func DecryptionClusterApplicationsYaml(path string, secretName string) (string, error) {
	_, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("the cluster does not have a applications.yaml file: %w", err)
	}
	applicationsY, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	applicationsC := &kustomizev1.Kustomization{}
	err = yaml.Unmarshal([]byte(applicationsY), &applicationsC)
	if err != nil {
		return "", err
	}
	if applicationsC.Spec.Decryption != nil {
		return "", fmt.Errorf("decryption is already configured")
	}
	applicationsC.Spec.Decryption = &kustomizev1.Decryption{
		Provider:  "sops",
		SecretRef: &meta.LocalObjectReference{Name: secretName},
	}
	applicationsY, err = yaml.Marshal(applicationsC)
	if err != nil {
		return "", err
	}
	return string(applicationsY), nil
}
