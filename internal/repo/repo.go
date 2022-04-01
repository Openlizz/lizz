package repo

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	gogitv5 "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"gitlab.com/openlizz/lizz/internal/git"
	"gitlab.com/openlizz/lizz/internal/git/gogit"
)

func Clone(
	URL string,
	branch string,
	username string,
	password string,
	privateKeyFile string,
	timeout time.Duration,
) (*gogit.GoGit, error) {
	nURL, err := url.Parse(URL)
	if err != nil {
		return nil, err
	}
	gitAuth, err := transportForURL(nURL, username, password, privateKeyFile)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// Lazy go-git repository
	tmpDir, err := os.MkdirTemp("", "lizz-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary working dir: %w", err)
	}
	git := gogit.New(tmpDir, gitAuth)
	var caBundle []byte
	cloned, err := git.Clone(ctx, nURL.String(), branch, caBundle)
	if err != nil {
		return nil, err
	}
	if cloned == false {
		return nil, fmt.Errorf("no error while cloning the repository but cloned false")
	}
	return git, nil
}

func CommitPush(
	g *gogit.GoGit,
	authorName string,
	authorEmail string,
	message string,
	destinationUrl string,
	timeout time.Duration,
) error {
	_, err := g.Commit(git.Commit{
		Author: git.Author{
			Name:  authorName,
			Email: authorEmail,
		},
		Message: message,
	})
	if err != nil && err != git.ErrNoStagedFiles {
		return fmt.Errorf("failed to commit: %w", err)
	}
	var remoteName string
	if destinationUrl == "" {
		remoteName = gogitv5.DefaultRemoteName
	} else {
		remoteName, err = g.CreateRemote(destinationUrl, "destination")
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var caBundle []byte
	err = g.Push(ctx, remoteName, caBundle)
	if err != nil {
		if err.Error() != "non-fast-forward update: refs/heads/main" &&
			err.Error() != "already up-to-date" {
			return fmt.Errorf("failed to push: %w", err)
		}
	}
	return nil
}

// transportForURL constructs a transport.AuthMethod based on the scheme
// of the given URL and the configured flags. If the protocol equals
// "ssh" but no private key is configured, authentication using the local
// SSH-agent is attempted.
func transportForURL(
	u *url.URL,
	username string,
	password string,
	privateKeyFile string,
) (transport.AuthMethod, error) {
	switch u.Scheme {
	case "https":
		return &http.BasicAuth{
			Username: username,
			Password: password,
		}, nil
	case "ssh":
		if privateKeyFile != "" {
			return ssh.NewPublicKeysFromFile(u.User.Username(), privateKeyFile, password)
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("scheme %q is not supported", u.Scheme)
	}
}
