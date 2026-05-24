<div align="center">

# ComSarif

[![Go Reference](https://pkg.go.dev/badge/github.com/typisttech/comsarif.svg)](https://pkg.go.dev/github.com/typisttech/comsarif)
[![GitHub Release](https://img.shields.io/github/v/release/typisttech/comsarif?style=flat-square&)](https://github.com/typisttech/comsarif/releases/latest)
[![Test](https://github.com/typisttech/comsarif/actions/workflows/test.yml/badge.svg)](https://github.com/typisttech/comsarif/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/typisttech/comsarif/graph/badge.svg?token=2YOGJ8FGFB)](https://codecov.io/gh/typisttech/comsarif)
[![License](https://img.shields.io/github/license/typisttech/comsarif.svg)](https://github.com/typisttech/comsarif/blob/master/LICENSE)
[![Follow @TangRufus on X](https://img.shields.io/badge/Follow-TangRufus-15202B?logo=x&logoColor=white)](https://x.com/tangrufus)
[![Follow @TangRufus.com on Bluesky](https://img.shields.io/badge/Bluesky-TangRufus.com-blue?logo=bluesky)](https://bsky.app/profile/tangrufus.com)
[![Sponsor @TangRufus via GitHub](https://img.shields.io/badge/Sponsor-TangRufus-EA4AAA?logo=githubsponsors)](https://github.com/sponsors/tangrufus)
[![Hire Typist Tech](https://img.shields.io/badge/Hire-Typist%20Tech-778899)](https://typist.tech/contact/)

<p>
  <strong>Convert Composer audit reports to SARIF files.</strong>
  <br />
  <br />
  Built with ♥ by <a href="https://typist.tech/">Typist Tech</a>
</p>

</div>

---

> [!TIP]
> **Hire Tang Rufus!**
>
> I am looking for my next role, freelance or full-time.
> If you find this tool useful, I can build you more weird stuff like this.
> Let's talk if you are hiring PHP / Ruby / Go developers.
>
> Contact me at https://typist.tech/contact/

---

## Goal

Convert [Composer audit reports](https://getcomposer.org/doc/03-cli.md#audit) to SARIF files,
so that they can be uploaded to GitHub as [code scanning alerts](https://docs.github.com/en/code-security/concepts/code-scanning/about-code-scanning-alerts).

## CLI Usage

```bash
USAGE:
  comsarif [<flags>...] --audit <audit.json> --lock <composer.lock>

FLAGS:
  -audit string
        path to Composer audit JSON
  -lock string
        path to composer.lock
  -root string
        path to repository root. Default to current directory
  -v    Print version
  -version
        Print version

EXAMPLES:
  # Generate SARIF based on composer.lock
  $ composer audit --locked --format json > audit.json
  $ comsarif --audit audit.json --lock composer.lock

  # Generate SARIF based on installed packages
  $ composer install
  $ composer audit --format json > audit.json
  $ comsarif --audit audit.json --lock composer.lock
```

## GitHub Actions Usage

Refer to [composer-audit-to-sarif-action](https://github.com/typisttech/composer-audit-to-sarif-action).

## Library Usage

[![Go Reference](https://pkg.go.dev/badge/github.com/typisttech/comsarif.svg)](https://pkg.go.dev/github.com/typisttech/comsarif)

Refer to [Go Reference on pkg.go.dev](https://pkg.go.dev/github.com/typisttech/comsarif#section-documentation).

> [!TIP]
> **Hire Tang Rufus!**
>
> There is no need to understand any of these quirks.
> Let me handle them for you.
> I am seeking my next job, freelance or full-time.
>
> If you are hiring PHP / Ruby / Go developers,
> contact me at https://typist.tech/contact/

### CLI Installation

#### Homebrew (macOS / Linux) (Recommended)

```bash
brew install typisttech/tap/comsarif
```

#### Build from Source

```bash
go install github.com/typisttech/comsarif/cmd/comsarif@latest
```

#### Linux (Debian & Alpine)

Follow the instructions on https://broadcasts.cloudsmith.com/typisttech/oss

![Cloudsmith](https://img.shields.io/badge/OSS%20hosting%20by-cloudsmith-blue?logo=cloudsmith&style=flat-square&link=https%3A%2F%2Fcloudsmith.com)

Package repository hosting is graciously provided by [Cloudsmith](https://cloudsmith.com).
Cloudsmith is the only fully hosted, cloud-native, universal package management solution, that
enables your organization to create, store and share packages in any format, to any place, with total
confidence.

## Credits

[ComSarif](https://github.com/typisttech/comsarif) is a [Typist Tech](https://typist.tech) project and maintained by [Tang Rufus](https://x.com/TangRufus), freelance developer for [hire](https://typist.tech/contact/).

Full list of contributors can be found [here](https://github.com/typisttech/comsarif/graphs/contributors).

## Copyright and License

This project is a [free software](https://www.gnu.org/philosophy/free-sw.en.html) distributed under the terms of the MIT license. For the full license, see [LICENSE](./LICENSE).

## Contribute

Feedbacks / bug reports / pull requests are welcome.
