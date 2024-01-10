// Copyright 2024 Contrast Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/contrast-security-oss/contrast-go-installer/internal/installer"
)

const usageString = `usage: %[1]s <version>

contrast-go-installer is a utility for downloading and installing contrast-go.
Installation is based on the values of GOOS, GOARCH, and GOBIN, as seen by 'go env'.

Examples:
	%[1]s latest
	%[1]s 2.8.0

For a full list of available versions, please visit:
	https://docs.contrastsecurity.com/en/go-agent-release-notes-and-archive.html
`

var flags = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

func usage() {
	cmd := filepath.Base(os.Args[0])

	log.Printf(usageString, cmd)
}

type goenv struct {
	GOOS   string
	GOARCH string
	GOBIN  string
	GOPATH string
}

// `go env -json GOOS GOARCH GOBIN GOPATH` to collect settings
func getEnv() (*goenv, error) {
	installedGo, err := exec.LookPath("go")
	if err != nil {
		return nil, fmt.Errorf("unable to locate go installation: %w", err)
	}

	cmd := exec.Command(installedGo, "env", "-json", "GOOS", "GOARCH", "GOBIN", "GOPATH")
	var stdout, stderr bytes.Buffer

	cmd.Stderr = &stderr
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		if stderr.Len() != 0 {
			return nil, fmt.Errorf("unable to run 'go env': %w\n\t%s", err, stderr.String())
		}
		return nil, fmt.Errorf("unable to run 'go env': %w", err)
	}

	env := new(goenv)
	if err := json.Unmarshal(stdout.Bytes(), env); err != nil {
		return env, fmt.Errorf("unexpected 'go env' output: %w", err)
	}

	return env, nil
}

func main() {
	os.Exit(main1())
}

func main1() int {
	log.SetFlags(0)
	flags.Usage = usage
	// this is used in testing to avoid having to talk to a real server
	source := flags.String("u", "https://pkg.contrastsecurity.com/go-agent-release", "")

	flags.Parse(os.Args[1:])
	if len(flags.Args()) != 1 {
		flags.Usage()
		return 2
	}

	version := flags.Args()[0]

	env, err := getEnv()
	if err != nil {
		log.Printf("There was a problem reading the Go environment: %s", err)
		return 2
	}

	path, err := targetDir(env.GOBIN, env.GOPATH)
	if err != nil {
		log.Printf("Unable to find install path: %s", err)
		return 2
	}
	path = filepath.Join(path, "contrast-go")

	err = installer.Install(*source, version, env.GOOS, env.GOARCH, path)
	if err != nil && env.GOOS == "darwin" && env.GOARCH == "arm64" {
		// No darwin/arm64 binary? Try darwin/amd64. We don't do the same for
		// linux/arm64 since linux doesn't automagically translate binaries.
		bp := &installer.ErrBadPlatform{}
		if errors.As(err, &bp) {
			log.Println(
				"darwin/arm64 is not a release target for this contrast-go version.",
				"Setting release to darwin/amd64 to run in compatibility mode.",
			)
			env.GOARCH = "amd64"
			err = installer.Install(*source, version, env.GOOS, env.GOARCH, path)
		}
	}

	if err != nil {
		log.Println(err)
		return 2
	}

	log.Printf(
		"Downloaded '%s' release for %s/%s to %s.\n",
		version, env.GOOS, env.GOARCH, path,
	)

	return 0
}

// targetDir copies some of the logic in cmd/go/internal/modload/init.go to
// figure out where 'go install' would put things.
func targetDir(gobin, path string) (string, error) {
	if gobin != "" {
		return gobin, nil
	}

	list := filepath.SplitList(path)
	// This means that there is no $GOPATH env var and that the default wasn't
	// useable for some reason. From 'go help gopath':
	//
	// 		If the environment variable is unset, GOPATH defaults
	// 		to a subdirectory named "go" in the user's home directory
	// 		($HOME/go on Unix, %USERPROFILE%\go on Windows),
	// 		unless that directory holds a Go distribution.
	// 		Run "go env GOPATH" to see the current GOPATH.
	//
	// We might be in the twilight zone if this happens because 'go env' likely
	// won't succeed if it can't locate a GOPATH; we won't get this far.
	if len(list) == 0 {
		return "", errors.New("'go env GOBIN' and 'go env GOPATH' were empty")
	}

	return filepath.Join(list[0], "bin"), nil
}
