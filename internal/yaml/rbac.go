package yaml

import (
	"bytes"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

const (
	tenantLabel = "toolkit.fluxcd.io/tenant"
)

func NewRbacYaml(namespace string, tenant string, roleName string, clusterRole bool, serviceAccountName string) (string, error) {
	if err := validation.IsQualifiedName(tenant); len(err) > 0 {
		return "", fmt.Errorf("invalid tenant name '%s': %v", tenant, err)
	}
	if err := validation.IsQualifiedName(namespace); len(err) > 0 {
		return "", fmt.Errorf("invalid namespace '%s': %v", namespace, err)
	}
	if err := validation.IsQualifiedName(serviceAccountName); len(err) > 0 {
		return "", fmt.Errorf("invalid service account name '%s': %v", namespace, err)
	}
	namespaceC := corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   namespace,
			Labels: map[string]string{tenantLabel: tenant},
		},
	}
	accountC := corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName,
			Namespace: namespace,
			Labels:    map[string]string{tenantLabel: tenant},
		},
	}
	var rbacY string
	var err error
	if clusterRole {
		roleC := rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-reconciler", tenant),
				Namespace: namespace,
				Labels:    map[string]string{tenantLabel: tenant},
			},
			Subjects: []rbacv1.Subject{
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "User",
					Name:     fmt.Sprintf("gotk:%s:reconciler", namespace),
				},
				{
					Kind:      "ServiceAccount",
					Name:      serviceAccountName,
					Namespace: namespace,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     roleName,
			},
		}
		rbacY, err = exportTenantWithClusterRoleBinding(namespaceC, accountC, roleC)
	} else {
		roleC := rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-reconciler", tenant),
				Namespace: namespace,
				Labels:    map[string]string{tenantLabel: tenant},
			},
			Subjects: []rbacv1.Subject{
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "User",
					Name:     fmt.Sprintf("gotk:%s:reconciler", namespace),
				},
				{
					Kind:      "ServiceAccount",
					Name:      serviceAccountName,
					Namespace: namespace,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     roleName,
			},
		}
		rbacY, err = exportTenantWithRoleBinding(namespaceC, accountC, roleC)
	}
	if err != nil {
		return "", err
	}
	return rbacY, nil
}

func exportTenantWithRoleBinding(namespace corev1.Namespace, account corev1.ServiceAccount, roleBinding rbacv1.RoleBinding) (string, error) {
	var builder strings.Builder
	namespace.TypeMeta = metav1.TypeMeta{
		APIVersion: "v1",
		Kind:       "Namespace",
	}
	data, err := yaml.Marshal(namespace)
	if err != nil {
		return "", err
	}
	builder.WriteString("---\n")
	data = bytes.Replace(data, []byte("spec: {}\n"), []byte(""), 1)
	builder.WriteString(resourceToString(data))
	account.TypeMeta = metav1.TypeMeta{
		APIVersion: "v1",
		Kind:       "ServiceAccount",
	}
	data, err = yaml.Marshal(account)
	if err != nil {
		return "", err
	}
	builder.WriteString("---\n")
	data = bytes.Replace(data, []byte("spec: {}\n"), []byte(""), 1)
	builder.WriteString(resourceToString(data))
	roleBinding.TypeMeta = metav1.TypeMeta{
		APIVersion: "rbac.authorization.k8s.io/v1",
		Kind:       "RoleBinding",
	}
	data, err = yaml.Marshal(roleBinding)
	if err != nil {
		return "", err
	}
	builder.WriteString("---\n")
	builder.WriteString(resourceToString(data))
	return builder.String(), nil
}

func exportTenantWithClusterRoleBinding(namespace corev1.Namespace, account corev1.ServiceAccount, clusterRoleBinding rbacv1.ClusterRoleBinding) (string, error) {
	var builder strings.Builder
	namespace.TypeMeta = metav1.TypeMeta{
		APIVersion: "v1",
		Kind:       "Namespace",
	}
	data, err := yaml.Marshal(namespace)
	if err != nil {
		return "", err
	}
	builder.WriteString("---\n")
	data = bytes.Replace(data, []byte("spec: {}\n"), []byte(""), 1)
	builder.WriteString(resourceToString(data))
	account.TypeMeta = metav1.TypeMeta{
		APIVersion: "v1",
		Kind:       "ServiceAccount",
	}
	data, err = yaml.Marshal(account)
	if err != nil {
		return "", err
	}
	builder.WriteString("---\n")
	data = bytes.Replace(data, []byte("spec: {}\n"), []byte(""), 1)
	builder.WriteString(resourceToString(data))
	clusterRoleBinding.TypeMeta = metav1.TypeMeta{
		APIVersion: "rbac.authorization.k8s.io/v1",
		Kind:       "ClusterRoleBinding",
	}
	data, err = yaml.Marshal(clusterRoleBinding)
	if err != nil {
		return "", err
	}
	builder.WriteString("---\n")
	builder.WriteString(resourceToString(data))
	return builder.String(), nil
}
