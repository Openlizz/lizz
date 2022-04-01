package yaml

import (
	"errors"
	"os"

	kustomizePatch "sigs.k8s.io/kustomize/pkg/patch"
	kustomize "sigs.k8s.io/kustomize/pkg/types"
	"sigs.k8s.io/yaml"
)

func AddApplicationsYaml(path string, name string) (string, error) {
	var applicationsC kustomize.Kustomization
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		applicationsC = kustomize.Kustomization{
			Resources:             []string{},
			PatchesStrategicMerge: []kustomizePatch.StrategicMerge{},
		}

	} else {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		applicationsCPtr := &kustomize.Kustomization{}
		err = yaml.Unmarshal([]byte(data), &applicationsCPtr)
		if err != nil {
			return "", err
		}
		applicationsC = *applicationsCPtr
	}
	applicationsC.Resources = appendStringIfMissing(applicationsC.Resources, "./base/"+name)
	applicationsC.PatchesStrategicMerge = appendStrategicMergeIfMissing(
		applicationsC.PatchesStrategicMerge,
		kustomizePatch.StrategicMerge(name+"-patch.yaml"),
	)
	applicationsY, err := exportKustomization(applicationsC)
	if err != nil {
		return "", err
	}
	return applicationsY, nil
}

func RemoveApplicationsYaml(path string, name string) (string, error) {
	var applicationsC kustomize.Kustomization
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		applicationsC = kustomize.Kustomization{
			Resources:             []string{},
			PatchesStrategicMerge: []kustomizePatch.StrategicMerge{},
		}

	} else {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		applicationsCPtr := &kustomize.Kustomization{}
		err = yaml.Unmarshal([]byte(data), &applicationsCPtr)
		if err != nil {
			return "", err
		}
		applicationsC = *applicationsCPtr
	}
	applicationsC.Resources = removeString(applicationsC.Resources, "./base/"+name)
	applicationsC.PatchesStrategicMerge = removeStrategicMerge(
		applicationsC.PatchesStrategicMerge,
		name+"-patch.yaml",
	)
	applicationsY, err := exportKustomization(applicationsC)
	if err != nil {
		return "", err
	}
	return applicationsY, nil

}

func appendStringIfMissing(slice []string, elem string) []string {
	for _, ele := range slice {
		if ele == elem {
			return slice
		}
	}
	return append(slice, elem)
}

func appendStrategicMergeIfMissing(
	slice []kustomizePatch.StrategicMerge,
	elem kustomizePatch.StrategicMerge,
) []kustomizePatch.StrategicMerge {
	for _, ele := range slice {
		if ele == elem {
			return slice
		}
	}
	return append(slice, elem)
}

func removeString(slice []string, name string) []string {
	for idx, str := range slice {
		if str == name {
			slice[idx] = slice[len(slice)-1]
			return slice[:len(slice)-1]
		}
	}
	return slice
}

func removeStrategicMerge(
	slice []kustomizePatch.StrategicMerge,
	name string,
) []kustomizePatch.StrategicMerge {
	for idx, str := range slice {
		if str == kustomizePatch.StrategicMerge(name) {
			slice[idx] = slice[len(slice)-1]
			return slice[:len(slice)-1]
		}
	}
	return slice
}
