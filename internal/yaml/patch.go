package yaml

import (
	"bytes"
	"fmt"
	"strings"

	kustomizev1 "github.com/fluxcd/kustomize-controller/api/v1beta2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

func NewPatchYaml(namespace string, name string, path string) (string, error) {
	patchC := kustomizev1.Kustomization{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: kustomizev1.KustomizationSpec{
			Path: path,
		},
	}
	patchY, err := exportPatch(patchC)
	if err != nil {
		return "", err
	}
	return patchY, nil
}

func UpdatePathPatchYaml(patchY, path string) (string, error) {
	patchC, err := importPatch(patchY)
	if err != nil {
		return "", fmt.Errorf("error while importPatch: %w", err)
	}
	patchC.Spec.Path = path
	patchY, err = exportPatch(patchC)
	if err != nil {
		return "", err
	}
	return patchY, nil
}

func exportPatch(kustomization kustomizev1.Kustomization) (string, error) {
	var builder strings.Builder
	kustomization.TypeMeta = metav1.TypeMeta{
		APIVersion: "kustomize.toolkit.fluxcd.io/v1beta2",
		Kind:       "Kustomization",
	}
	data, err := yaml.Marshal(kustomization)
	if err != nil {
		return "", err
	}
	data = bytes.Replace(data, []byte("interval: 0s\n"), []byte(""), 1)
	data = bytes.Replace(data, []byte("prune: false\n"), []byte(""), 1)
	data = bytes.Replace(data, []byte("sourceRef:\n"), []byte(""), 1)
	data = bytes.Replace(data, []byte("kind: \"\"\n"), []byte(""), 1)
	data = bytes.Replace(data, []byte("name: \"\"\n"), []byte(""), 1)
	builder.WriteString(resourceToString(data))
	return builder.String(), nil
}

func importPatch(patchY string) (kustomizev1.Kustomization, error) {
	kustomization := &kustomizev1.Kustomization{}
	err := yaml.Unmarshal([]byte(patchY), kustomization)
	if err != nil {
		return kustomizev1.Kustomization{}, err
	}
	return *kustomization, nil
}
