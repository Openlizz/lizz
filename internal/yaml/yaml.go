package yaml

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"go.mozilla.org/sops/v3"
	"go.mozilla.org/sops/v3/aes"
	"go.mozilla.org/sops/v3/age"
	"go.mozilla.org/sops/v3/cmd/sops/common"
	"go.mozilla.org/sops/v3/keys"
	"go.mozilla.org/sops/v3/keyservice"
)

func Save(yaml string, path string) error {
	err := os.MkdirAll(filepath.Dir(path), os.ModePerm)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	l, err := f.WriteString(yaml)
	if err != nil {
		f.Close()
		return err
	}
	if l == 0 {
		f.Close()
		return fmt.Errorf("yaml file saved but empty.")
	}
	err = f.Close()
	if err != nil {
		return err
	}
	return nil
}

func EncryptYaml(fileName string, keyP string) (string, error) {
	svcs := []keyservice.KeyServiceClient{
		keyservice.NewLocalClient(),
	}
	key, err := age.MasterKeyFromRecipient(keyP)
	if err != nil {
		return "", err
	}
	groups := []sops.KeyGroup{[]keys.MasterKey{key}}
	var threshold int
	inputStore := common.DefaultStoreForPathOrFormat(fileName, "yaml")
	outputStore := common.DefaultStoreForPathOrFormat(fileName, "yaml")
	yamlE, err := Encrypt(EncryptOpts{
		OutputStore:    outputStore,
		InputStore:     inputStore,
		InputPath:      fileName,
		Cipher:         aes.NewCipher(),
		EncryptedRegex: "^(data|stringData)$",
		KeyServices:    svcs,
		KeyGroups:      groups,
		GroupThreshold: threshold,
	})
	if err != nil {
		return "", err
	}
	return string(yamlE), nil
}

func resourceToString(data []byte) string {
	data = bytes.Replace(data, []byte("  creationTimestamp: null\n"), []byte(""), 1)
	data = bytes.Replace(data, []byte("status: {}\n"), []byte(""), 1)
	return string(data)
}
