rpmreproduce
===

```
usage: rpmreproduce.py [-h] [--output OUTPUT] [--builder BUILDER] [--extra-repository-file EXTRA_REPOSITORY_FILE]
                       [--extra-repository-key EXTRA_REPOSITORY_KEY] [--gpg-sign-keyid GPG_SIGN_KEYID] [--gpg-verify]
                       [--gpg-verify-key GPG_VERIFY_KEY] [--proxy PROXY] [--no-checksums-verification] [--verbose] [--debug]
                       buildinfo

Given a buildinfo file from a RPM package, generate instructions for attempting to reproduce the binary packages built from the
associated source and build information.

positional arguments:
  buildinfo             Input buildinfo file. Local or remote file.

optional arguments:
  -h, --help            show this help message and exit
  --output OUTPUT       Directory for the build artifacts
  --builder BUILDER     Which building software should be used. (default: none)
  --extra-repository-file EXTRA_REPOSITORY_FILE
                        Add repository file content to the list of apt sources during the package build.
  --extra-repository-key EXTRA_REPOSITORY_KEY
                        Add key file (.asc) to the list of trusted keys during the package build.
  --gpg-sign-keyid GPG_SIGN_KEYID
                        GPG keyid to use for signing in-toto metadata.
  --gpg-verify          Verify buildinfo GPG signature.
  --gpg-verify-key GPG_VERIFY_KEY
                        GPG key to use for buildinfo GPG check.
  --proxy PROXY         Proxy address to use.
  --no-checksums-verification
                        Don't fail on checksums verification between original and rebuild packages
  --verbose             Display logger info messages.
  --debug               Display logger debug messages
```

`rpmreproduce` can parse buildinfo file having GPG signature and verify its signature with provided key file.

#### EXAMPLES

```
$ ./rpmreproduce.py --output=./artifacts --builder=mock tests/data/qubes-core-agent-4.1.23-1.fc33.x86_64.buildinfo
```

####  BUILDERS

`rpmreproduce` can use different backends to perform the actual package rebuild.
The desired backend is chosen using the --builder option. The default is `none`.

    none            Dry-run mode. No build is performed.

    mock            Use mock to build the package. This requires the
                    user to be in `mock` group.

> Note: Ensure to have `dev` option for the mount point where OUTPUT is. If not, `mock` will fail with
> such error like: `/dev/null: Permission denied`.
