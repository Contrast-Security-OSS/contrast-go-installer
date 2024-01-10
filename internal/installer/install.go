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

package installer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	artifactPath = "/%s/%s-%s/contrast-go"

	agentArchivePg = `For a full list of versions, see
	https://docs.contrastsecurity.com/en/go-agent-release-notes-and-archive.html`

	badver            = `Version %q does not exist. ` + agentArchivePg
	sysRequirementsPg = `For system requirements, see
	https://docs.contrastsecurity.com/en/go-system-requirements.html`

	agentInstallPg = "https://docs.contrastsecurity.com/en/install-go.html"
	unknownError   = `Sorry, something strange happened. Please try again later or
install manually. For the latter, see the instructions at
` + agentInstallPg
)

// Install attempts to download a release of contrast-go matching version, os,
// and arch into path and chmod it to an executable.
func Install(baseURL, version, os, arch, path string) error {
	id := installData{
		baseURL: baseURL,
		version: version,
		os:      os,
		arch:    arch,
		dst:     path,
	}
	tmp, err := id.download()
	if err != nil {
		return err
	}

	return id.install(tmp, nil)
}

type installData struct {
	baseURL string
	version string // version to download
	os      string // target os
	arch    string // target arch
	dst     string // final destination

	tmpdir string // set during testing to facilitate cleanup, otherwise empty
}

// download to a temp location, returning the temp file's location
func (id *installData) download() (string, error) {
	url := fmt.Sprintf(id.baseURL+artifactPath, id.version, id.os, id.arch)
	tmp, err := os.CreateTemp(id.tmpdir, "contrast-go*")
	if err != nil {
		return "", fmt.Errorf("unable to create tmp for download: %w", err)
	}
	defer tmp.Close()
	res, err := makeRequest(http.MethodHead, url)
	if err != nil {
		return "", err
	}
	if res.StatusCode == http.StatusNotFound {
		return "", id.dlNotFoundError(res)
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf(
			"server did not return 200 for %v: %v",
			url, res.Status,
		)
	}
	wantHash := res.Header.Get("X-Checksum-Sha256")

	res, err = makeRequest(http.MethodGet, url)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	hash := sha256.New()
	if n, err := io.Copy(io.MultiWriter(tmp, hash), res.Body); err != nil {
		return "", fmt.Errorf(
			"couldn't download file (%d bytes read of %d expected): %w",
			n, res.ContentLength, err,
		)
	}

	gotHash := hex.EncodeToString(hash.Sum(nil))
	if wantHash != gotHash {
		return "", fmt.Errorf("checksum mismatch, expected %q instead of %q", wantHash, gotHash)
	}

	fi, err := os.Stat(tmp.Name())
	if err != nil {
		return "", fmt.Errorf("cannot verify download: %w", err)
	}
	if res.ContentLength > -1 && fi.Size() != res.ContentLength {
		return "", fmt.Errorf(
			"downloaded file size %v does not match expected value %d",
			fi.Size(),
			res.ContentLength,
		)
	}
	return tmp.Name(), nil
}

// move from temp location to final
func (id installData) install(tmpFile string, lookupFunc func() (string, error)) error {
	if lookupFunc == nil {
		// pass in custom lookup function for testing
		lookupFunc = func() (string, error) {
			return exec.LookPath("contrast-go")
		}
	}
	if err := os.MkdirAll(filepath.Dir(id.dst), 0755); err != nil {
		return fmt.Errorf("installation directory issue: %w", err)
	}
	if err := os.Rename(tmpFile, id.dst); err != nil {
		return err
	}

	if err := os.Chmod(id.dst, 0755); err != nil {
		return fmt.Errorf("permission issue: %w", err)
	}

	path, err := lookupFunc()
	if err != nil {
		return fmt.Errorf(
			`contrast-go was installed at %s, but this location was not found in $PATH.
Make sure that the $PATH environment variable includes %s`,
			id.dst,
			id.dst,
		)
	}
	if path != id.dst {
		return fmt.Errorf(
			"contrast-go installed at %s, but shadowed in path by %s",
			id.dst,
			path,
		)
	}

	return nil
}

func makeRequest(method, url string) (*http.Response, error) {
	client := http.DefaultClient
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "contrast-go-installer/0")
	response, responseErr := client.Do(req)

	if netErr := new(net.OpError); errors.As(responseErr, &netErr) {
		return response, fmt.Errorf("there is a network communication issue: %s", responseErr)
	}

	return response, responseErr
}

// determine what went wrong and return a nice error for the user
func (id installData) dlNotFoundError(res *http.Response) error {
	// first, check the version
	url := fmt.Sprintf("%s/%s", id.baseURL, id.version)
	res2, err := makeRequest(http.MethodGet, url)
	if err != nil {
		return fmt.Errorf(badver, id.version)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		// invalid version; tell user what versions are valid
		res2, err = makeRequest(http.MethodGet, id.baseURL)
		if err != nil {
			return fmt.Errorf(badver, id.version)
		}
		defer res2.Body.Close()
		if res2.StatusCode != http.StatusOK {
			return fmt.Errorf(badver, id.version)
		}
		avail, err := listVersions(res2.Body)
		if err != nil {
			return fmt.Errorf(badver, id.version)
		}

		return &ErrBadVersion{
			AvailableVersions: avail,
			BadVersion:        id.version,
		}
	}

	avail, err := listPlatforms(res2.Body)
	if err != nil || len(avail) < 2 {
		return fmt.Errorf(unknownError)
	}
	// os and/or arch is invalid
	return &ErrBadPlatform{
		Available: avail,
		Arch:      id.arch,
		OS:        id.os,
	}
}

// reads html from body, returning extracted platforms
func listPlatforms(body io.Reader) ([]string, error) {
	var plats []string
	subdirs, err := htmlDir(body)
	if err != nil {
		return nil, err
	}
	for _, sub := range subdirs {
		if !strings.Contains(sub, "-") {
			// all platforms contain a dash: os-arch. throw away anything else.
			continue
		}
		plats = append(plats, sub)
	}
	return plats, nil
}

type ErrBadPlatform struct {
	Available []string
	Arch, OS  string
}

func (err *ErrBadPlatform) Error() string {
	return fmt.Sprintf("contrast-go is not available for platform \"%s-%s\". Available platforms:\n\t%s\n%s",
		err.OS, err.Arch, strings.Join(err.Available, ", "), sysRequirementsPg)
}
