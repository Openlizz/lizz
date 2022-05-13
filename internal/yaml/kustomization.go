package yaml

import (
	"strings"

	kustomize "sigs.k8s.io/kustomize/pkg/types"
	"sigs.k8s.io/yaml"
)

func NewKustomizationYaml(decryption bool, sourceSecret bool) (string, error) {
	resources := []string{"rbac.yaml"}
	if sourceSecret == true {
		resources = append(resources, "sourcesecret.yaml")
	}
	resources = append(resources, "sync.yaml")
	if decryption == true {
		resources = append(resources, "secret.yaml")
	}
	kustomizeC := kustomize.Kustomization{
		Resources: resources,
	}
	kustomizeY, err := ExportKustomization(kustomizeC)
	if err != nil {
		return "", err
	}
	return kustomizeY, nil
}

func ReadKustomization(y string) (kustomize.Kustomization, error) {
	k := &kustomize.Kustomization{}
	err := yaml.Unmarshal([]byte(y), &k)
	if err != nil {
		return kustomize.Kustomization{}, err
	}
	return *k, nil
}

func ExportKustomization(kustomization kustomize.Kustomization) (string, error) {
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
