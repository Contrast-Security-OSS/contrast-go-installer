# contrast-go-installer

`contrast-go-installer` downloads and installs Contrast Security's
[contrast-go](https://docs.contrastsecurity.com/en/go.html), which is used to
instrument web applications to detect vulnerabilities at runtime. It chooses the
correct contrast-go release for your OS and architecture, and downloads the
requested version.

Click for a [demo of contrast-go](http://www.youtube.com/watch?v=ffBWozHhASw).

A full list of contrast-go releases can be found at
https://pkg.contrastsecurity.com/go-agent-release/.

## System Requirements

* go1.25 or later, which can be downloaded from https://go.dev/dl/.

> **Note**
> While `contrast-go-installer` works with version 1.25 and on, `contrast-go`
requires one of the two latest Go major versions. For a full list of
contrast-go's system requirements, see [OS and architecture
requirements](https://docs.contrastsecurity.com/en/go-system-requirements.html).

## Usage

To install the latest `contrast-go` version: 
```sh
go run github.com/contrast-security-oss/contrast-go-installer@latest latest
```

To install a specific `contrast-go` version: 
```sh
go run github.com/contrast-security-oss/contrast-go-installer@latest 3.1.0
```

The install location will be `$GOBIN` if set, otherwise `$GOPATH/bin`. To change
the install location, override `$GOBIN` when running the command:

```sh
GOBIN=/path/to/dir go run github.com/contrast-security-oss/contrast-go-installer@latest 3.1.0
```
<!-- NOTE: blank lines are *required* around markdown blocks inside <details>, or it won't render as markdown -->

## Additional Help

If you experience any issues with installation, or have any questions for the
team, please contact us via our [support
portal](https://support.contrastsecurity.com/hc/en-us)
