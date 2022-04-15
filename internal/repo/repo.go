package repo

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fluxcd/go-git-providers/gitprovider"
	gogitv5 "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"gitlab.com/openlizz/lizz/internal/git"
	"gitlab.com/openlizz/lizz/internal/git/gogit"
	"gitlab.com/openlizz/lizz/internal/logger/cli"
	"gitlab.com/openlizz/lizz/internal/provider"
)

var (
	ErrReconciledWithWarning = errors.New("reconciled with warning")
)

type CreateOptions struct {
	RepositoryName string
	Owner          string
	TransportType  string
	Branch         string
	Timeout        time.Duration
	Personal       bool
	Description    string
	Visibility     string
	Reconcile      bool
	Teams          map[string]string
	SshHostname    string
	Provider       gitprovider.Client
}

type CloneOptions struct {
	URL            string
	RepositoryName string
	Owner          string
	TransportType  string
	Branch         string
	Username       string
	Password       string
	PrivateKeyFile string
	Timeout        time.Duration
	Personal       bool
	Description    string
	Visibility     string
	Reconcile      bool
	Teams          map[string]string
	ReadWriteKey   bool
	CaBundle       []byte
	SshHostname    string
	Provider       gitprovider.Client
}

func Create(options *CreateOptions, status *cli.Status) (string, gitprovider.UserRepository, error) {
	if status != nil {
		status.Start("Create new repository ")
		defer status.End(false)
	}
	ctx, cancel := context.WithTimeout(context.Background(), options.Timeout)
	defer cancel()
	var repo gitprovider.UserRepository
	var err error
	if options.Personal {
		repo, err = options.reconcileUserRepository(ctx)
	} else {
		repo, err = options.reconcileOrgRepository(ctx)
	}
	if err != nil && !errors.Is(err, ErrReconciledWithWarning) {
		return "", nil, err
	}
	if options.TransportType == "" {
		options.TransportType = "ssh"
	}
	URL, err := getCloneURL(repo, gitprovider.TransportType(options.TransportType), options.SshHostname)
	if err != nil {
		return "", nil, err
	}
	if status != nil {
		status.End(true)
	}
	return URL, repo, nil
}

func Clone(options *CloneOptions) (*gogit.GoGit, error) {
	ctx, cancel := context.WithTimeout(context.Background(), options.Timeout)
	defer cancel()
	tmpDir, err := os.MkdirTemp("", "lizz-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary working dir: %w", err)
	}

	var nURL *url.URL
	var git *gogit.GoGit
	if options.RepositoryName != "" && options.Owner != "" {
		createOptions := &CreateOptions{
			RepositoryName: options.RepositoryName,
			Owner:          options.Owner,
			Branch:         options.Branch,
			Timeout:        options.Timeout,
			Personal:       options.Personal,
			Description:    options.Description,
			Visibility:     options.Visibility,
			Reconcile:      options.Reconcile,
			Teams:          options.Teams,
			SshHostname:    options.SshHostname,
			Provider:       options.Provider,
		}
		URL, _, err := Create(createOptions, nil)
		if err != nil {
			return nil, err
		}
		nURL, err = url.Parse(URL)
		if err != nil {
			return nil, err
		}
		git = gogit.New(tmpDir, &http.BasicAuth{
			Username: options.Owner,
			Password: options.Password,
		})

	} else if options.URL != "" {
		var err error
		nURL, err = url.Parse(options.URL)
		if err != nil {
			return nil, err
		}
		gitAuth, err := transportForURL(nURL, options.Username, options.Password, options.PrivateKeyFile)
		if err != nil {
			return nil, err
		}
		git = gogit.New(tmpDir, gitAuth)
	} else {
		return nil, fmt.Errorf("options should contain an URL or a repository name and a owner. URL is %s, RepositoryName is %s, and Owner is %s.", options.URL, options.RepositoryName, options.Owner)
	}
	cloned, err := git.Clone(ctx, nURL.String(), options.Branch, options.CaBundle)
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

// Most of the code above is coming from https://github.com/fluxcd/flux2

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

// getCloneURL returns the Git clone URL for the given
// gitprovider.UserRepository. If the given transport type is
// gitprovider.TransportTypeSSH and a custom SSH hostname is configured,
// the hostname of the URL will be modified to this hostname.
func getCloneURL(repository gitprovider.UserRepository, transport gitprovider.TransportType, sshHostname string) (string, error) {
	var url string
	if cloner, ok := repository.(gitprovider.CloneableURL); ok {
		url = cloner.GetCloneURL("", transport)
	} else {
		url = repository.Repository().GetCloneURL(transport)
	}

	var err error
	if transport == gitprovider.TransportTypeSSH && sshHostname != "" {
		if url, err = setHostname(url, sshHostname); err != nil {
			err = fmt.Errorf("failed to set SSH hostname for URL %q: %w", url, err)
		}
	}
	return url, err
}

// setHostname is a helper to replace the hostname of the given URL.
// TODO(hidde): support for this should be added in go-git-providers.
func setHostname(URL, hostname string) (string, error) {
	u, err := url.Parse(URL)
	if err != nil {
		return URL, err
	}
	u.Host = hostname
	return u.String(), nil
}

// reconcileOrgRepository reconciles a gitprovider.OrgRepository
// with the CreateOptions values, including any
// gitprovider.TeamAccessInfo configurations.
//
// If one of the gitprovider.TeamAccessInfo does not reconcile
// successfully, the gitprovider.UserRepository and an
// ErrReconciledWithWarning error are returned.
func (opts *CreateOptions) reconcileOrgRepository(ctx context.Context) (gitprovider.UserRepository, error) {
	// Construct the repository and other configuration objects
	// go-git-provider likes to work with
	subOrgs, repoName := splitSubOrganizationsFromRepositoryName(opts.RepositoryName)
	orgRef, err := opts.getOrganization(ctx, subOrgs)
	if err != nil {
		return nil, fmt.Errorf("failed to create new Git repository %q: %w", opts.RepositoryName, err)
	}
	repoRef := newOrgRepositoryRef(*orgRef, repoName)
	repoInfo := newRepositoryInfo(opts.Description, opts.Branch, opts.Visibility)

	// Reconcile the organization repository
	repo, err := opts.Provider.OrgRepositories().Get(ctx, repoRef)
	if err != nil {
		if !errors.Is(err, gitprovider.ErrNotFound) {
			return nil, fmt.Errorf("failed to get Git repository %q: %w", repoRef.String(), err)
		}
		// go-git-providers has at present some issues with the idempotency
		// of the available Reconcile methods, and setting e.g. the default
		// branch correctly. Resort to Create until this has been resolved.
		repo, err = opts.Provider.OrgRepositories().Create(ctx, repoRef, repoInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to create new Git repository %q: %w", repoRef.String(), err)
		}
	}

	if opts.Reconcile {
		// Set default branch before calling Reconcile due to bug described
		// above.
		repoInfo.DefaultBranch = repo.Get().DefaultBranch
		if err = retry(1, 2*time.Second, func() (err error) {
			repo, _, err = opts.Provider.OrgRepositories().Reconcile(ctx, repoRef, repoInfo)
			return
		}); err != nil {
			return nil, fmt.Errorf("failed to reconcile Git repository %q: %w", repoRef.String(), err)
		}
	}

	// Build the team access config
	teamAccessInfo, err := buildTeamAccessInfo(opts.Teams, gitprovider.RepositoryPermissionVar(gitprovider.RepositoryPermissionMaintain))
	if err != nil {
		return nil, fmt.Errorf("failed to reconcile repository team access: %w", err)
	}

	// Reconcile the team access config on best effort (that being:
	// record the error as a warning, but continue with the
	// reconciliation of the others)
	var warning error
	if count := len(teamAccessInfo); count > 0 {
		for _, i := range teamAccessInfo {
			var err error
			// Don't reconcile team if team already exists and opts.reconcile is false
			if team, err := repo.TeamAccess().Get(ctx, i.Name); err == nil && !opts.Reconcile && team != nil {
				continue
			}
			_, _, err = repo.TeamAccess().Reconcile(ctx, i)
			if err != nil {
				warning = fmt.Errorf("failed to grant permissions to team: %w", ErrReconciledWithWarning)
			}
		}
	}
	return repo, warning
}

// reconcileUserRepository reconciles a gitprovider.UserRepository
// with the CreateOptions values. It returns the reconciled
// gitprovider.UserRepository, or an error.
func (opts *CreateOptions) reconcileUserRepository(ctx context.Context) (gitprovider.UserRepository, error) {
	// Construct the repository and other metadata objects
	// go-git-provider likes to work with.
	_, repoName := splitSubOrganizationsFromRepositoryName(opts.RepositoryName)
	userRef := newUserRef(opts.Provider.SupportedDomain(), opts.Owner)
	repoRef := newUserRepositoryRef(userRef, repoName)
	repoInfo := newRepositoryInfo(opts.Description, opts.Branch, opts.Visibility)

	// Reconcile the user repository
	repo, err := opts.Provider.UserRepositories().Get(ctx, repoRef)
	if err != nil {
		if !errors.Is(err, gitprovider.ErrNotFound) {
			return nil, fmt.Errorf("failed to get Git repository %q: %w", repoRef.String(), err)
		}
		// go-git-providers has at present some issues with the idempotency
		// of the available Reconcile methods, and setting e.g. the default
		// branch correctly. Resort to Create until this has been resolved.
		repo, err = opts.Provider.UserRepositories().Create(ctx, repoRef, repoInfo)
		if err != nil {
			return nil, fmt.Errorf("failed to create new Git repository %q: %w", repoRef.String(), err)
		}
	}

	if opts.Reconcile {
		// Set default branch before calling Reconcile due to bug described
		// above.
		repoInfo.DefaultBranch = repo.Get().DefaultBranch
		if err = retry(1, 2*time.Second, func() (err error) {
			repo, _, err = opts.Provider.UserRepositories().Reconcile(ctx, repoRef, repoInfo)
			return
		}); err != nil {
			return nil, fmt.Errorf("failed to reconcile Git repository %q: %w", repoRef.String(), err)
		}
	}

	return repo, nil
}

// getOrganization retrieves and returns the gitprovider.Organization
// using the CreateOptions values.
func (opts *CreateOptions) getOrganization(ctx context.Context, subOrgs []string) (*gitprovider.OrganizationRef, error) {
	orgRef := newOrganizationRef(opts.Provider.SupportedDomain(), opts.Owner, subOrgs)
	// With Stash get the organization to be sure to get the correct key
	if string(opts.Provider.ProviderID()) == string(provider.GitProviderStash) {
		org, err := opts.Provider.Organizations().Get(ctx, orgRef)
		if err != nil {
			return nil, fmt.Errorf("failed to get Git organization: %w", err)
		}

		orgRef = org.Organization()

		return &orgRef, nil
	}
	return &orgRef, nil
}

// splitSubOrganizationsFromRepositoryName removes any prefixed sub
// organizations from the given repository name by splitting the
// string into a slice by '/'.
// The last (or only) item of the slice result is assumed to be the
// repository name, other items (nested) sub organizations.
func splitSubOrganizationsFromRepositoryName(name string) ([]string, string) {
	elements := strings.Split(name, "/")
	i := len(elements)
	switch i {
	case 1:
		return nil, name
	default:
		return elements[:i-1], elements[i-1]
	}
}

// buildTeamAccessInfo constructs a gitprovider.TeamAccessInfo slice
// from the given string map of team names to permissions.
//
// Providing a default gitprovider.RepositoryPermission is optional,
// and omitting it will make it default to the go-git-provider default.
//
// An error is returned if any of the given permissions is invalid.
func buildTeamAccessInfo(m map[string]string, defaultPermissions *gitprovider.RepositoryPermission) ([]gitprovider.TeamAccessInfo, error) {
	var infos []gitprovider.TeamAccessInfo
	if defaultPermissions != nil {
		if err := gitprovider.ValidateRepositoryPermission(*defaultPermissions); err != nil {
			return nil, fmt.Errorf("invalid default team permission %q", *defaultPermissions)
		}
	}
	for n, p := range m {
		permission := defaultPermissions
		if p != "" {
			p := gitprovider.RepositoryPermission(p)
			if err := gitprovider.ValidateRepositoryPermission(p); err != nil {
				return nil, fmt.Errorf("invalid permission %q for team %q", p, n)
			}
			permission = &p
		}
		i := gitprovider.TeamAccessInfo{
			Name:       n,
			Permission: permission,
		}
		infos = append(infos, i)
	}
	return infos, nil
}

// newOrganizationRef constructs a gitprovider.OrganizationRef with the
// given values and returns the result.
func newOrganizationRef(domain, organization string, subOrganizations []string) gitprovider.OrganizationRef {
	return gitprovider.OrganizationRef{
		Domain:           domain,
		Organization:     organization,
		SubOrganizations: subOrganizations,
	}
}

// newOrgRepositoryRef constructs a gitprovider.OrgRepositoryRef with
// the given values and returns the result.
func newOrgRepositoryRef(organizationRef gitprovider.OrganizationRef, name string) gitprovider.OrgRepositoryRef {
	return gitprovider.OrgRepositoryRef{
		OrganizationRef: organizationRef,
		RepositoryName:  name,
	}
}

// newUserRef constructs a gitprovider.UserRef with the given values
// and returns the result.
func newUserRef(domain, login string) gitprovider.UserRef {
	return gitprovider.UserRef{
		Domain:    domain,
		UserLogin: login,
	}
}

// newUserRepositoryRef constructs a gitprovider.UserRepositoryRef with
// the given values and returns the result.
func newUserRepositoryRef(userRef gitprovider.UserRef, name string) gitprovider.UserRepositoryRef {
	return gitprovider.UserRepositoryRef{
		UserRef:        userRef,
		RepositoryName: name,
	}
}

// newRepositoryInfo constructs a gitprovider.RepositoryInfo with the
// given values and returns the result.
func newRepositoryInfo(description, defaultBranch, visibility string) gitprovider.RepositoryInfo {
	var i gitprovider.RepositoryInfo
	if description != "" {
		i.Description = gitprovider.StringVar(description)
	}
	if defaultBranch != "" {
		i.DefaultBranch = gitprovider.StringVar(defaultBranch)
	}
	if visibility != "" {
		i.Visibility = gitprovider.RepositoryVisibilityVar(gitprovider.RepositoryVisibility(visibility))
	}
	return i
}

func retry(retries int, wait time.Duration, fn func() error) (err error) {
	for i := 0; ; i++ {
		err = fn()
		if err == nil {
			return
		}
		if i >= retries {
			break
		}
		time.Sleep(wait)
	}
	return err
}
