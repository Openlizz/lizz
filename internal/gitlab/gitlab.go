package gitlab

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

const (
	DefaultPermission = "maintain"
	DefaultDomain     = "gitlab.com"
	tokenEnvVar       = "GITLAB_TOKEN"
	ProjectRegex      = `\A[[:alnum:]\x{00A9}-\x{1f9ff}_][[:alnum:]\p{Pd}\x{00A9}-\x{1f9ff}_\.]*\z`
)

func GetToken() (string, error) {
	glToken := os.Getenv(tokenEnvVar)
	if glToken == "" {
		var err error
		glToken, err = readPasswordFromStdin("Please enter your GitLab personal access token (PAT): ")
		if err != nil {
			return "", fmt.Errorf("could not read token: %w", err)
		}
	}
	return glToken, nil
}

// readPasswordFromStdin reads a password from stdin and returns the input
// with trailing newline and/or carriage return removed. It also makes sure that terminal
// echoing is turned off if stdin is a terminal.
func readPasswordFromStdin(prompt string) (string, error) {
	var out string
	var err error
	fmt.Fprint(os.Stdout, prompt)
	stdinFD := int(os.Stdin.Fd())
	if term.IsTerminal(stdinFD) {
		var inBytes []byte
		inBytes, err = term.ReadPassword(int(os.Stdin.Fd()))
		out = string(inBytes)
	} else {
		out, err = bufio.NewReader(os.Stdin).ReadString('\n')
	}
	if err != nil {
		return "", fmt.Errorf("could not read from stdin: %w", err)
	}
	return strings.TrimRight(out, "\r\n"), nil
}
