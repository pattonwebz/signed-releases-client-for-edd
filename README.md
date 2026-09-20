# Signed Releases Client for EDD

Verifies [minisign](https://jedisct1.github.io/minisign/) (Ed25519)
signatures on plugin release zips **before** WordPress installs them,
guarding the update path against a compromised store. Companion to the
Signed Releases for EDD store extension, which serves the signatures.

- **Fail closed** — a missing signature is treated exactly like an invalid
  one; stripping the signature never bypasses verification.
- **Version binding + downgrade ratchet** — the authenticated trusted
  comment binds slug and version, so a compromised store cannot replay
  another plugin's package, an older release, or anything below the
  installed version *once that floor is established* (see the
  `current_version` note below — a fresh install with no floor yet can
  still be walked up to any validly-signed release at or above zero,
  including an older vulnerable one, until the first verified update sets
  the high-water mark).
- **Release-race tolerant** — if the package was replaced between a site's
  cached update check and the download, the guard fetches the store's
  current signature and accepts a strictly newer verified release.
- **Zero production dependencies** — plain PSR-4 PHP.
- **Staged rollout** — `log` mode observes without blocking; `enforce`
  blocks; a runtime filter is the kill switch.
- **Key revocation** (optional) — a store-served, root-signed revocation
  manifest locks out a stolen signing key while every other pinned key
  (your pre-staged successor) keeps verifying. Append-only on the client
  with its own log-before-enforce rollout.

## Requirements

- PHP 7.4+
- WordPress 5.5+ (the guard reads `$hook_extra` on `upgrader_pre_download`)
- The `sodium_*` functions — present on every WordPress ≥ 5.2 install,
  natively via ext-sodium or through core's bundled polyfill

## Install

```sh
composer require pattonwebz/signed-releases-client-for-edd
```

Published on
[Packagist](https://packagist.org/packages/pattonwebz/signed-releases-client-for-edd)
— no custom repository configuration needed.

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

`current_version` is optional in name only — omit it and a fresh install
has no downgrade floor until the first verified update sets one (see
Compatibility contract below). If you don't already have the running
version handy, derive it instead of skipping it:

```php
'current_version' => get_plugin_data( MY_PLUGIN_FILE )['Version'],
```

`register()` never throws, even with a malformed `$args` (a bad key
string, a missing required key). A misconfiguration must not be able to
white-screen the site it's protecting — instead it returns `null`,
blocks *this plugin's* updates (fail closed) when the plugin file was at
least identifiable, and surfaces the problem via an always-visible
`admin_notices` warning plus an `error_log()` line.

The mode can be adjusted at runtime without a release — per plugin or for
all of them:

```php
add_filter( 'srcl_mode', fn( $mode, $slug ) => 'log', 10, 2 );
```

A runtime override is a supported escape hatch, but it is never silent: the
guard tracks the effective mode per slug (option
`srcl_mode_seen`, checked on every update poll via
`set_site_transient_update_plugins` and again on every download), and any
switchover — an override appearing, changing, or going away — is logged
(warning while an override is active, info on return to the configured mode)
and announced via the `srcl_mode_switched` action
(`$slug, $previous, $effective, $configured`). An *invalid* filter return is
refused outright and falls back to the configured mode with a warning.

### Key revocation

Pin the revocation root key alongside your package keys to enable it:

```php
UpdaterGuard::register( array(
    // ... args as above ...
    'public_keys'         => array( $active_key, $successor_key ),
    'revocation_root_key' => 'RWS...revocation root public key...',
    'revocation_mode'     => 'log', // its own rollout, independent of 'mode'.
) );
```

The root key is deliberately **not** a `public_keys` entry: it signs only
revocation manifests, never packages, so a stolen root cannot sign malware
— it can only subtract trust (and a suspected-compromised root is replaced
by a normal release updating this pinned value). On each update pass the
guard fetches the store's manifest (`?edd_action=get_revocation_manifest`),
verifies it against the root, and merges it into a durable cache
(`srcl_revocations`). A package signed by a revoked
key then fails with `revoked_key`; your other pinned keys — pin a standing
successor from day one — keep verifying, which is what turns a stolen-key
incident into an ordinary update instead of a locked-out fleet.

Client semantics worth knowing:

- **Append-only union.** A later manifest that merely omits a previously
  revoked key restores nothing; only an explicit, root-signed
  `unrevoked_keys` entry un-revokes.
- **Anti-rollback.** A monotonic manifest `sequence` is ratcheted; replayed
  older manifests are ignored and logged.
- **Silent-safe fetch.** A failed manifest fetch keeps the cache and never
  blocks or warns: revocation state is monotonic, so stale is never wrong.
- **Own rollout.** `revocation_mode` (`off`/`log`/`enforce`, default `log`)
  is independent of `mode`, with its own runtime filter
  `srcl_revocation_mode`. In `log` a revoked-key
  match is logged but still verifies — soak it before letting it block.

### Uninstalling a consumer

Whatever else your `uninstall.php` cleans up, it must leave these two options
alone:

- `srcl_seen` — the high-water mark that feeds the
  downgrade floor.
- `srcl_revocations` — the append-only, ratcheted
  revocation cache.

Both are ratchets, not caches. Deleting them resets the site's floor to
whatever version happens to be installed — reopening the window for a store
to walk the site *backwards* to an older signed release — and re-arms keys
that were revoked. The update path keeps looking healthy the whole time, so
nothing surfaces until it matters.

They are also shared rather than per-plugin: `_seen` (and the failures and
mode options) is a single option holding one key per slug, and
`_revocations` is not slug-keyed at all. An uninstall routine that deletes
the option outright therefore disarms every consumer on the site, not just
the plugin being removed, and the others have no way to notice. Removing
only your own slug key from `_seen` is at least self-inflicted, but there is
no good reason to do even that. The failures and mode bookkeeping
(`srcl_failures`,
`srcl_mode_seen`) is harmless either way.

## How verification works

On a plugin update the guard downloads the package itself, then requires,
in order: a structurally valid signature (from the update response, or
fetched from the store's public endpoint), Ed25519 verification over the
zip's BLAKE2b-512 hash against a pinned public key, the signed trusted
comment matching the configured slug, and a signed version that is the
offered version (or newer) and never below the installed/previously-seen
floor. Any failure logs (`log` mode) or aborts the install with the old
version intact (`enforce` mode).

The signature itself comes from whichever of three sources answers first:
the update transient's own `signature` property (present only if your EDD
updater class copies the full API response onto the transient — confirmed
true for the classic `EDD_SL_Plugin_Updater`, not independently verified
for every `edd-sl-sdk`-based updater), the store's public endpoint for the
offered version, or — as a release-race healer — the store's endpoint for
whatever version is live right now. The endpoint fallbacks don't depend on
your updater class at all, so verification works regardless of which one
your plugin uses.

## Compatibility contract

This package ships un-prefixed. When several active plugins each bundle a
copy, PHP loads each class once — from whichever plugin's autoloader runs
first — so **the first-loaded copy serves every consumer on the site**.
That model is deliberate and rests on one hard promise: **within a major
version, nothing breaks.**

- The public API only grows: no removed or renamed classes/methods, no new
  required constructor args, no changed defaults that alter verification
  outcomes.
- The persisted option formats (`srcl_seen`, `srcl_failures`,
  `srcl_mode_seen` — slug-keyed arrays — and `srcl_revocations`, shared
  store-wide, not slug-keyed) are frozen.
- Hook names and signatures (`srcl_mode`, `srcl_revocation_mode`,
  `srcl_verified`, `srcl_failure`, `srcl_mode_switched`) are frozen.

A breaking change means a new major version, and mixing majors across
plugins on one site is unsupported — ship a major bump across all your
plugins together. A site running one outdated plugin may execute that
stale copy's verification code; keeping plugins updated is the site's
responsibility, as it already is for updates generally.

The identifiers were renamed from the `pattonwebz_signed_releases_*` prefix
to `srcl_*` — options, hooks and the manifest format tags alike — in 0.3.0.
No released consumer ever used the earlier names, so there is nothing to
migrate: if you are coming from 0.2.0 or earlier and wrote filters or set
options by hand, use the new names.

### Which copy is loaded

"The first-loaded copy serves every consumer" is easy to state and
impossible to observe. When behaviour looks like it is coming from a
version you did not expect, or you are diagnosing a plugin that pins an
older copy, ask PHP which file actually defines the class. The right host
is a must-use plugin, because it is not tied to any one consumer's
lifecycle: it loads before regular plugins, survives deactivating the
plugin under investigation, and cannot itself be switched off by the code
you are debugging.

```php
<?php
// wp-content/mu-plugins/signed-releases-loaded-from.php

add_action(
	'init',
	function () {
		if ( ! class_exists( '\PattonWebz\SignedReleases\UpdaterGuard' ) ) {
			return;
		}

		$loaded = new ReflectionClass( \PattonWebz\SignedReleases\UpdaterGuard::class );

		error_log( 'signed-releases: guard loaded from ' . $loaded->getFileName() );
	}
);
```

`init` is late enough that every consumer has registered its autoloader,
so the path printed is the winner: that file's code is what every plugin on
the site is running. If it is not the `vendor/` directory of the plugin you
are debugging, another plugin is serving it — expected when several of them
bundle the package, and only a problem when the two copies are from
different major versions.

(Without a file to hand, the same question one-liner from the CLI:
`wp eval 'echo ( new ReflectionClass( "PattonWebz\\SignedReleases\\UpdaterGuard" ) )->getFileName(), "\n";'`)

## Development

```sh
composer install
composer test                                      # PHPUnit, no WordPress install needed
MINISIGN=/path/to/minisign tools/generate-fixtures.sh   # regenerate test fixtures
```

The keypairs in `tests/fixtures/` are test keys, committed on purpose.
Never sign a release with them.

## License

MIT. See [LICENSE](LICENSE).

This library ships no WordPress code and is MIT-licensed for reuse; when it is
bundled into a GPL plugin, that distributed plugin remains GPL as a whole.
