package cmd

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	netUrl "net/url"
	"os"
	"regexp"
	"strings"
	"time"

	gogitv5 "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"gitlab.com/openlizz/lizz/internal/git"
	"gitlab.com/openlizz/lizz/internal/git/gogit"
	kustomizePatch "sigs.k8s.io/kustomize/pkg/patch"
)

func cloneRepositoryTemp(url string, branch string, username string, password string, timeout time.Duration) (*gogit.GoGit, string, error) {

	repositoryURL, err := netUrl.Parse(url)
	if err != nil {
		return nil, "", err
	}
	gitAuth, err := transportForURL(repositoryURL, username, password)
	if err != nil {
		return nil, "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Lazy go-git repository
	tmpDir, err := os.MkdirTemp("", "lizz-add-")
	if err != nil {
		return nil, "", fmt.Errorf("failed to create temporary working dir: %w", err)
	}

	gitClient := gogit.New(tmpDir, gitAuth)
	logger.Actionf("cloning branch %q from Git repository %q", branch, url)
	var caBundle []byte
	cloned, err := gitClient.Clone(ctx, url, branch, caBundle)
	if err != nil {
		return nil, "", err
	}
	if cloned {
		logger.Successf("cloned repository")
	}
	return gitClient, tmpDir, nil
}

func commitAndpush(gitClient *gogit.GoGit, authorName string, authorEmail string, message string, branch string, destinationUrl string, timeout time.Duration) error {
	commit, err := gitClient.Commit(git.Commit{
		Author: git.Author{
			Name:  authorName,
			Email: authorEmail,
		},
		Message: message,
	})
	if err != nil && err != git.ErrNoStagedFiles {
		return fmt.Errorf("failed to commit: %w", err)
	}
	if err == nil {
		logger.Successf("committed to %q (%q)", branch, commit)
	} else {
		logger.Successf("files are up to date")
	}
	var remoteName string
	if destinationUrl == "" {
		remoteName = gogitv5.DefaultRemoteName
	} else {

		logger.Actionf("creating destination remote to %q", destinationUrl)
		remoteName, err = gitClient.CreateRemote(destinationUrl, "destination")
		if err != nil {
			return err
		}
		logger.Successf("created remote")
	}
	logger.Actionf("pushing to remote %q", remoteName)
	ctx, cancel := context.WithTimeout(context.Background(), rootArgs.timeout)
	defer cancel()
	var caBundle []byte
	err = gitClient.Push(ctx, remoteName, caBundle)
	if err != nil {
		if err.Error() != "non-fast-forward update: refs/heads/main" && err.Error() != "already up-to-date" {
			return fmt.Errorf("failed to push: %w", err)
		}
	}
	return nil
}

// transportForURL constructs a transport.AuthMethod based on the scheme
// of the given URL and the configured flags. If the protocol equals
// "ssh" but no private key is configured, authentication using the local
// SSH-agent is attempted.
func transportForURL(u *url.URL, username string, password string) (transport.AuthMethod, error) {
	switch u.Scheme {
	case "https":
		return &http.BasicAuth{
			Username: username,
			Password: password,
		}, nil
	// case "ssh":
	// 	if bootstrapArgs.privateKeyFile != "" {
	// 		return ssh.NewPublicKeysFromFile(u.User.Username(), bootstrapArgs.privateKeyFile, gitArgs.password)
	// 	}
	// 	return nil, nil
	default:
		return nil, fmt.Errorf("scheme %q is not supported", u.Scheme)
	}
}

func resourceToString(data []byte) string {
	data = bytes.Replace(data, []byte("  creationTimestamp: null\n"), []byte(""), 1)
	data = bytes.Replace(data, []byte("status: {}\n"), []byte(""), 1)
	return string(data)
}

func appendApplicationIfMissing(slice []Application, elem Application) []Application {
	for _, ele := range slice {
		if ele.Repository == elem.Repository && ele.Name == ele.Name {
			return slice
		}
	}
	return append(slice, elem)
}

func removeApplicationByName(slice []Application, name string) []Application {
	for idx, app := range slice {
		if app.Name == name {
			slice[idx] = slice[len(slice)-1]
			return slice[:len(slice)-1]
		}
	}
	return slice
}

func appendStringIfMissing(slice []string, elem string) []string {
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

func appendStrategicMergeIfMissing(slice []kustomizePatch.StrategicMerge, elem kustomizePatch.StrategicMerge) []kustomizePatch.StrategicMerge {
	for _, ele := range slice {
		if ele == elem {
			return slice
		}
	}
	return append(slice, elem)
}

func removeStrategicMerge(slice []kustomizePatch.StrategicMerge, name string) []kustomizePatch.StrategicMerge {
	for idx, str := range slice {
		if str == kustomizePatch.StrategicMerge(name) {
			slice[idx] = slice[len(slice)-1]
			return slice[:len(slice)-1]
		}
	}
	return slice
}

func extractValuesFromString(config string) string {
	startIndex := strings.Index(config, "values:")
	if startIndex == -1 {
		// no values -> check that dependencies and dependsOn are also empty
		return ""
	} else {
		startIndex += len("values:")
		r, _ := regexp.Compile("\n[^( \t)]")
		endIndex := r.FindStringIndex(config[startIndex:])
		if endIndex == nil {
			endIndex = []int{len(config) - startIndex}
		}
		return strings.ReplaceAll(config[startIndex:startIndex+endIndex[0]], "\t", "  ")
	}
}
