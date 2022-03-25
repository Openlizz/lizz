package yaml

import (
	"fmt"
	"time"

	"filippo.io/age"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

func NewSecretSopsYaml(name string) (string, *age.X25519Identity, error) {
	// generate Age key (code from https://github.com/FiloSottile/age/blob/4169274d045d1ca198e09ef40d317cb6a5dfb7c4/cmd/age-keygen/keygen.go#L123)
	k, err := age.GenerateX25519Identity()
	if err != nil {
		return "", &age.X25519Identity{}, fmt.Errorf("internal error: %v", err)
	}
	agekey := fmt.Sprintf("# created: %s\n", time.Now().Format(time.RFC3339))
	agekey += fmt.Sprintf("# public key: %s\n", k.Recipient())
	agekey += fmt.Sprintf("%s\n", k)
	secretC := corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "flux-system",
		},
		Data: map[string][]byte{"age.agekey": []byte(agekey)},
	}
	secretY, err := yaml.Marshal(secretC)
	if err != nil {
		return "", &age.X25519Identity{}, err
	}
	return string(secretY), k, nil
}
