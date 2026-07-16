# Signed Releases Client

Verifies [minisign](https://jedisct1.github.io/minisign/) (Ed25519)
signatures on plugin release zips before WordPress installs them, guarding
the update path against a compromised store. Companion to the
**Signed Releases for EDD** store extension, which serves the signatures.

- **Fail closed**: a missing signature is treated exactly like an invalid
  one — stripping the signature never bypasses verification.
- **Version binding + downgrade ratchet**: the authenticated trusted comment
  binds slug and version; a compromised store cannot replay another
  plugin's package, an older release, or anything below the installed
  version.
- **Release-race tolerant**: if the package was replaced between a site's
  cached update check and the download, the guard fetches the store's
  current signature and accepts a strictly newer verified release.
- **No production dependencies**: PHP >= 7.4 and the `sodium_*` functions
  every WordPress >= 5.2 provides (natively or via its bundled polyfill).
- **`log` / `enforce` modes** with a runtime kill-switch filter, for staged
  rollouts.

This repository is a read-only subtree split of the
[`signed-zips-edd`](https://github.com/pattonwebz/signed-zips-edd) monorepo —
issues and changes belong there.

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

UpdaterGuard::register( array(
    'plugin_file'     => plugin_basename( MY_PLUGIN_FILE ),
    'slug'            => 'my-plugin',
    'store_url'       => 'https://store.example',
    'public_keys'     => array( MY_PLUGIN_SIGNING_PUBKEY ),
    'item_id'         => 123,
    'current_version' => MY_PLUGIN_VERSION,
    'mode'            => 'log', // then 'enforce' once a clean cycle is observed.
) );
```

See `docs/plugin-integration.md` in the monorepo for the full integration
guide, key distribution, and rollout sequence.

## If several of your plugins bundle this package

Two plugins each shipping `PattonWebz\SignedReleases` under their own
`vendor/` means whichever loads first wins — silent version skew. If more
than one plugin on the same sites will bundle this, prefix it per plugin at
build time with [Strauss](https://github.com/BrianHenryIE/strauss) (or
PHP-Scoper); the package is plain PSR-4 and prefixes cleanly.

## Development

Tests live in the monorepo and travel with the split:

```sh
composer install && composer test
```

The keypairs in `tests/fixtures/` are test keys, committed on purpose.
Never sign a release with them.
