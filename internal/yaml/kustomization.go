package yaml

import (
	"strings"

	kustomize "sigs.k8s.io/kustomize/pkg/types"
	"sigs.k8s.io/yaml"
)

func NewKustomizationYaml(decryption bool) (string, error) {
	var resources []string
	if decryption == true {
		resources = []string{"rbac.yaml", "sync.yaml", "secret.yaml"}
	} else {
		resources = []string{"rbac.yaml", "sync.yaml"}
	}
	kustomizeC := kustomize.Kustomization{
		Resources: resources,
	}
	kustomizeY, err := exportKustomization(kustomizeC)
	if err != nil {
		return "", err
	}
	return kustomizeY, nil
}

func exportKustomization(kustomization kustomize.Kustomization) (string, error) {
	var builder strings.Builder
	kustomization.TypeMeta = kustomize.TypeMeta{
		APIVersion: "kustomize.config.k8s.io/v1beta1",
		Kind:       "Kustomization",
	}
	data, err := yaml.Marshal(kustomization)
	if err != nil {
		return "", err
	}
	builder.WriteString(resourceToString(data))
	return builder.String(), nil
}
