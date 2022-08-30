package github

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

const (
	DefaultPermission = "maintain"
	DefaultDomain     = "github.com"
	tokenEnvVar       = "GITHUB_TOKEN"
)

func GetToken() (string, error) {
	ghToken := os.Getenv(tokenEnvVar)
	if ghToken == "" {
		var err error
		ghToken, err = readPasswordFromStdin("Please enter your GitHub personal access token (PAT): ")
		if err != nil {
			return "", fmt.Errorf("could not read token: %w", err)
		}
	}
	return ghToken, nil
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
