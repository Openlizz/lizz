/*
Copyright 2021 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gogit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/client"
	"github.com/go-git/go-git/v5/plumbing/transport/http"

	"github.com/openlizz/lizz/internal/git"
)

type GoGit struct {
	path       string
	auth       transport.AuthMethod
	repository *gogit.Repository
}

type CommitOptions struct {
	GpgKeyPath       string
	GpgKeyPassphrase string
	KeyID            string
}

func New(path string, auth transport.AuthMethod) *GoGit {
	return &GoGit{
		path: path,
		auth: auth,
	}
}

func (g *GoGit) Repository() *gogit.Repository {
	return g.repository
}

func (g *GoGit) Init(url, branch string) (bool, error) {
	if g.repository != nil {
		return false, nil
	}

	r, err := gogit.PlainInit(g.path, false)
	if err != nil {
		return false, err
	}
	if _, err = r.CreateRemote(&config.RemoteConfig{
		Name: gogit.DefaultRemoteName,
		URLs: []string{url},
	}); err != nil {
		return false, err
	}
	branchRef := plumbing.NewBranchReferenceName(branch)
	if err = r.CreateBranch(&config.Branch{
		Name:   branch,
		Remote: gogit.DefaultRemoteName,
		Merge:  branchRef,
	}); err != nil {
		return false, err
	}
	// PlainInit assumes the initial branch to always be master, we can
	// overwrite this by setting the reference of the Storer to a new
	// symbolic reference (as there are no commits yet) that points
	// the HEAD to our new branch.
	if err = r.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, branchRef)); err != nil {
		return false, err
	}

	g.repository = r
	return true, nil
}

func (g *GoGit) Clone(ctx context.Context, url, branch string, caBundle []byte) (bool, error) {
	branchRef := plumbing.ReferenceName("")
	if branch != "" {
		branchRef = plumbing.NewBranchReferenceName(branch)
	} else {
		ref, err := refFromRemoteHead(ctx, url, g.auth)
		if err != nil {
			return false, err
		}
		branchRef = ref
	}
	r, err := gogit.PlainCloneContext(ctx, g.path, false, &gogit.CloneOptions{
		URL:           url,
		Auth:          g.auth,
		RemoteName:    gogit.DefaultRemoteName,
		ReferenceName: branchRef,
		SingleBranch:  true,

		NoCheckout: false,
		Progress:   nil,
		Tags:       gogit.NoTags,
		CABundle:   caBundle,
	})
	if err != nil {
		if err == transport.ErrEmptyRemoteRepository ||
			isRemoteBranchNotFoundErr(err, branchRef.String()) {
			return g.Init(url, branch)
		}
		return false, err
	}

	g.repository = r
	return true, nil
}

func (g *GoGit) CheckoutToCommit(sha string) error {
	if g.repository == nil {
		return git.ErrNoGitRepository
	}
	wt, err := g.repository.Worktree()
	if err != nil {
		return err
	}
	err = wt.Checkout(&gogit.CheckoutOptions{
		Hash: plumbing.NewHash(sha),
	})
	return err
}

func (g *GoGit) Write(path string, reader io.Reader) error {
	if g.repository == nil {
		return git.ErrNoGitRepository
	}

	wt, err := g.repository.Worktree()
	if err != nil {
		return err
	}

	f, err := wt.Filesystem.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, reader)
	return err
}

func (g *GoGit) Commit(message git.Commit, opts ...git.Option) (string, error) {
	if g.repository == nil {
		return "", git.ErrNoGitRepository
	}

	wt, err := g.repository.Worktree()
	if err != nil {
		return "", err
	}

	status, err := wt.Status()
	if err != nil {
		return "", err
	}

	// apply the options
	options := &git.CommitOptions{}
	for _, opt := range opts {
		opt.ApplyToCommit(options)
	}

	// go-git has [a bug](https://github.com/go-git/go-git/issues/253)
	// whereby it thinks broken symlinks to absolute paths are
	// modified. There's no circumstance in which we want to commit a
	// change to a broken symlink: so, detect and skip those.
	var changed bool
	for file, _ := range status {
		abspath := filepath.Join(g.path, file)
		info, err := os.Lstat(abspath)
		if err != nil {
			// file has been removed and need to be added
			if errors.Is(err, os.ErrNotExist) {
				_, _ = wt.Add(file)
				changed = true
				continue
			} else {
				return "", fmt.Errorf("checking if %s is a symlink: %w", file, err)
			}
		}
		if info.Mode()&os.ModeSymlink > 0 {
			// symlinks are OK; broken symlinks are probably a result
			// of the bug mentioned above, but not of interest in any
			// case.
			if _, err := os.Stat(abspath); os.IsNotExist(err) {
				continue
			}
		}
		_, _ = wt.Add(file)
		changed = true
	}

	if !changed {
		head, err := g.repository.Head()
		if err != nil {
			return "", err
		}
		return head.Hash().String(), git.ErrNoStagedFiles
	}

	commitOpts := &gogit.CommitOptions{
		Author: &object.Signature{
			Name:  message.Name,
			Email: message.Email,
			When:  time.Now(),
		},
	}

	if options.GPGSigningInfo != nil {
		entity, err := getOpenPgpEntity(*options.GPGSigningInfo)
		if err != nil {
			return "", err
		}

		commitOpts.SignKey = entity
	}

	commit, err := wt.Commit(message.Message, commitOpts)
	if err != nil {
		return "", err
	}
	return commit.String(), nil
}

func (g *GoGit) Push(ctx context.Context, remoteName string, refSpecs []config.RefSpec, caBundle []byte) error {
	if g.repository == nil {
		return git.ErrNoGitRepository
	}
	return g.repository.PushContext(ctx, &gogit.PushOptions{
		RemoteName: remoteName,
		RefSpecs:   refSpecs,
		Auth:       g.auth,
		Progress:   nil,
		CABundle:   caBundle,
	})
}

func (g *GoGit) Status() (bool, error) {
	if g.repository == nil {
		return false, git.ErrNoGitRepository
	}
	wt, err := g.repository.Worktree()
	if err != nil {
		return false, err
	}
	status, err := wt.Status()
	if err != nil {
		return false, err
	}
	return status.IsClean(), nil
}

func (g *GoGit) Head() (string, error) {
	if g.repository == nil {
		return "", git.ErrNoGitRepository
	}
	head, err := g.repository.Head()
	if err != nil {
		return "", err
	}
	return head.Hash().String(), nil
}

func (g *GoGit) CreateRemote(url, name string) (string, error) {
	if g.repository == nil {
		return "", git.ErrNoGitRepository
	}
	remote, err := g.repository.CreateRemote(&config.RemoteConfig{
		Name: name,
		URLs: []string{url},
	})
	if err != nil {
		return "", err
	}
	return remote.Config().Name, nil
}

func (g *GoGit) Path() string {
	return g.path
}

func (g *GoGit) SetAuth(username string, password string) {
	g.auth = &http.BasicAuth{
		Username: username,
		Password: password,
	}
}

func isRemoteBranchNotFoundErr(err error, ref string) bool {
	return strings.Contains(err.Error(), fmt.Sprintf("couldn't find remote ref %q", ref))
}

func getOpenPgpEntity(info git.GPGSigningInfo) (*openpgp.Entity, error) {
	r, err := os.Open(info.KeyRingPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open GPG key ring: %w", err)
	}

	entityList, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return nil, err
	}

	if len(entityList) == 0 {
		return nil, fmt.Errorf("empty GPG key ring")
	}

	var entity *openpgp.Entity
	if info.KeyID != "" {
		for _, ent := range entityList {
			if ent.PrimaryKey.KeyIdString() == info.KeyID {
				entity = ent
			}
		}

		if entity == nil {
			return nil, fmt.Errorf("no GPG private key matching key id '%s' found", info.KeyID)
		}
	} else {
		entity = entityList[0]
	}

	err = entity.PrivateKey.Decrypt([]byte(info.Passphrase))
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt GPG private key: %w", err)
	}

	return entity, nil
}

// from https://github.com/hairyhenderson/gomplate/pull/1217/files
// refFromRemoteHead - extract the ref from the remote HEAD, to work around
// hard-coded 'master' default branch in go-git.
// Should be unnecessary once https://github.com/go-git/go-git/issues/249 is
// fixed.
func refFromRemoteHead(ctx context.Context, url string, auth transport.AuthMethod) (plumbing.ReferenceName, error) {
	e, err := transport.NewEndpoint(url)
	if err != nil {
		return "", err
	}

	cli, err := client.NewClient(e)
	if err != nil {
		return "", err
	}

	s, err := cli.NewUploadPackSession(e, auth)
	if err != nil {
		return "", err
	}

	info, err := s.AdvertisedReferencesContext(ctx)
	if err != nil {
		return "", err
	}

	refs, err := info.AllReferences()
	if err != nil {
		return "", err
	}

	headRef, ok := refs["HEAD"]
	if !ok {
		return "", fmt.Errorf("no HEAD ref found")
	}

	return headRef.Target(), nil
}
