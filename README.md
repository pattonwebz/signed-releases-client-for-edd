# Signed Releases Client

Verifies [minisign](https://jedisct1.github.io/minisign/) (Ed25519)
signatures on plugin release zips **before** WordPress installs them,
guarding the update path against a compromised store. Companion to the
Signed Releases for EDD store extension, which serves the signatures.

- **Fail closed** — a missing signature is treated exactly like an invalid
  one; stripping the signature never bypasses verification.
- **Version binding + downgrade ratchet** — the authenticated trusted
  comment binds slug and version, so a compromised store cannot replay
  another plugin's package, an older release, or anything below the
  installed version.
- **Release-race tolerant** — if the package was replaced between a site's
  cached update check and the download, the guard fetches the store's
  current signature and accepts a strictly newer verified release.
- **Zero production dependencies** — plain PSR-4 PHP.
- **Staged rollout** — `log` mode observes without blocking; `enforce`
  blocks; a runtime filter is the kill switch.

## Requirements

- PHP 7.4+
- WordPress 5.5+ (the guard reads `$hook_extra` on `upgrader_pre_download`)
- The `sodium_*` functions — present on every WordPress ≥ 5.2 install,
  natively via ext-sodium or through core's bundled polyfill

## Install

```sh
composer require pattonwebz/signed-releases-client
```

While this repository is private, add it as a VCS repository first:

```json
{
    "repositories": [
        { "type": "vcs", "url": "git@github.com:pattonwebz/signed-releases-client.git" }
    ]
}
```

## Usage

```php
use PattonWebz\SignedReleases\UpdaterGuard;

add_action( 'init', function () {
    UpdaterGuard::register( array(
        'plugin_file'     => plugin_basename( MY_PLUGIN_FILE ),
        'slug'            => 'my-plugin', // must equal the slug CI signs.
        'store_url'       => 'https://store.example',
        'public_keys'     => array( 'RWS...base64 public key...' ),
        'item_id'         => 123,
        'current_version' => MY_PLUGIN_VERSION,
        'mode'            => 'log', // 'enforce' once a clean cycle is observed.
    ) );
} );
```

Register on `init` (like the EDD SL updater itself) so wp-cron
auto-updates are covered. Multiple keys are only for rotation windows.

The mode can be adjusted at runtime without a release — per plugin or for
all of them:

```php
add_filter( 'pattonwebz_signed_releases_mode', fn( $mode, $slug ) => 'log', 10, 2 );
```

## How verification works

On a plugin update the guard downloads the package itself, then requires,
in order: a structurally valid signature (from the update response, or
fetched from the store's public endpoint), Ed25519 verification over the
zip's BLAKE2b-512 hash against a pinned public key, the signed trusted
comment matching the configured slug, and a signed version that is the
offered version (or newer) and never below the installed/previously-seen
floor. Any failure logs (`log` mode) or aborts the install with the old
version intact (`enforce` mode).

## Compatibility contract

This package ships un-prefixed. When several active plugins each bundle a
copy, PHP loads each class once — from whichever plugin's autoloader runs
first — so **the first-loaded copy serves every consumer on the site**.
That model is deliberate and rests on one hard promise: **within a major
version, nothing breaks.**

- The public API only grows: no removed or renamed classes/methods, no new
  required constructor args, no changed defaults that alter verification
  outcomes.
- The persisted option formats (`pattonwebz_signed_releases_seen`,
  `pattonwebz_signed_releases_failures` — slug-keyed arrays) are frozen.
- Hook names and signatures (`pattonwebz_signed_releases_mode`,
  `_verified`, `_failure`) are frozen.

A breaking change means a new major version, and mixing majors across
plugins on one site is unsupported — ship a major bump across all your
plugins together. A site running one outdated plugin may execute that
stale copy's verification code; keeping plugins updated is the site's
responsibility, as it already is for updates generally.

## Development

```sh
composer install
composer test                                      # PHPUnit, no WordPress install needed
MINISIGN=/path/to/minisign tools/generate-fixtures.sh   # regenerate test fixtures
```

The keypairs in `tests/fixtures/` are test keys, committed on purpose.
Never sign a release with them.

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).
