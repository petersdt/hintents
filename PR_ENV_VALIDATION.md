# Environment Validation Command

This pull request adds a new `erst doctor` command that performs a
comprehensive check of the developer environment. The command now
covers the following items:

- ensures **Go** is installed and that the version matches the `go.mod`
  directive
- detects the presence of the **Rust** toolchain (`rustc`, `cargo`)
- locates the **simulator binary** (`erst-sim`)
- validates the **syntax** of any TOML configuration files
  (`.erst.toml`, `~/.erst.toml`, `/etc/erst/config.toml`)
- performs a **health ping** against the configured RPC endpoint

The output formats results in colored `[OK]`/`[FAIL]` lines and
provides fix hints when a problem is detected. The verbose flag
(`--verbose`) adds paths and error details.

Unit tests exercise the new checks and cover failure cases. Existing
functionality is unchanged.

---

## Screenshot / Proof

*(attach image showing successful `erst doctor` output below)*

![doctor-output](attachment://doctor.png)

> **How to include the attachment:**
> 1. Run `erst doctor` in your terminal and take a screenshot or save
>    the output as an image named `doctor.png`.
> 2. When creating the GitHub pull request, drag-and-drop the image file
>    into the description field or click the **Attach files by dragging
>    & dropping, selecting or pasting them.** area.
> 3. GitHub will upload the file and insert the markdown link above
>    automatically. You can also paste the image from clipboard directly.

Once the PR is opened you can update the image or add additional
screenshots as needed.
