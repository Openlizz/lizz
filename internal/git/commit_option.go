package git

// Option is a some configuration that modifies options for a commit.
type Option interface {
	// ApplyToCommit applies this configuration to a given commit option.
	ApplyToCommit(*CommitOptions)
}

// CommitOptions contains options for making a commit.
type CommitOptions struct {
	*GPGSigningInfo
}

// GPGSigningInfo contains information for signing a commit.
type GPGSigningInfo struct {
	KeyRingPath string
	Passphrase  string
	KeyID       string
}

type GpgSigningOption struct {
	*GPGSigningInfo
}

func (w GpgSigningOption) ApplyToCommit(in *CommitOptions) {
	in.GPGSigningInfo = w.GPGSigningInfo
}

func WithGpgSigningOption(path, passphrase, keyID string) Option {
	// Return nil if no path is set, even if other options are configured.
	if path == "" {
		return GpgSigningOption{}
	}

	return GpgSigningOption{
		GPGSigningInfo: &GPGSigningInfo{
			KeyRingPath: path,
			Passphrase:  passphrase,
			KeyID:       keyID,
		},
	}
}
