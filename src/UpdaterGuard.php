<?php
/**
 * Verifies EDD-delivered update packages before WordPress installs them.
 *
 * Hooks `upgrader_pre_download` (WordPress >= 5.5 for the $hook_extra arg),
 * scoped to a single plugin. When that plugin is being updated, the guard
 * downloads the package itself, verifies the minisign signature against the
 * pinned public keys, and hands WordPress either the verified file or a
 * WP_Error (enforce mode) that aborts the install with the old version intact.
 *
 * The signature is looked up in three places, in order, moving on whenever
 * verification fails with the current candidate:
 *  1. a `signature` property on the plugin's row in the update_plugins
 *     transient (present when the store injects it into the EDD SL
 *     get_version response), then
 *  2. the store's public signature endpoint for the offered version, then
 *  3. the endpoint's signature for the store's *current* version — which
 *     heals the release race where the package was replaced in place
 *     between this site's cached version check and the download.
 *     (Endpoint: ?edd_action=get_release_signature — served by the
 *     "Signed Releases for EDD" store extension.)
 *
 * A missing signature is treated exactly like an invalid one — otherwise
 * stripping the signature would bypass verification entirely.
 *
 * Key revocation (optional; active when `revocation_root_key` is configured):
 * alongside the signature fetch, the guard fetches the store's revocation
 * manifest (?edd_action=get_revocation_manifest), verifies it against the
 * pinned revocation root key — a separate trust root that never signs
 * packages — and merges it into a durable append-only cache. Signatures made
 * by a revoked key then fail with REVOKED_KEY exactly like an untrusted key
 * would, while every other pinned key (the standing successor) keeps
 * verifying. A failed manifest fetch is silent by design: revocation state
 * is monotonic, so a stale cache is never wrong, only possibly incomplete.
 */

declare(strict_types=1);

namespace PattonWebz\SignedReleases;

final class UpdaterGuard {

	/*
	 * COMPATIBILITY CONTRACT — this package ships un-prefixed in several
	 * plugins at once and the first-loaded copy serves them all. These
	 * option names, their slug-keyed array shapes, and the
	 * pattonwebz_signed_releases_{mode,revocation_mode,verified,failure}
	 * hook signatures are frozen: changing any of them within a major
	 * version breaks co-installed plugins running another copy. The same
	 * applies to RevocationList::OPTION_REVOCATIONS and its shape. See
	 * README.
	 */
	public const OPTION_FAILURES = 'pattonwebz_signed_releases_failures';

	/** Highest signed version verified per slug — the downgrade ratchet. */
	public const OPTION_SEEN = 'pattonwebz_signed_releases_seen';

	/** A .minisig is well under 1 KB; anything bigger is not a signature. */
	private const MAX_SIGNATURE_BYTES = 8192;

	/**
	 * A revocation-manifest envelope (manifest JSON + its .minisig) for a
	 * shop's worth of keys fits in a few KB; anything bigger is not one.
	 */
	private const MAX_MANIFEST_BYTES = 16384;

	/** The envelope format the manifest endpoint serves. */
	private const MANIFEST_ENVELOPE_FORMAT = 'pattonwebz-revocation-envelope-v1';

	/** Plugin basename, e.g. "my-plugin/my-plugin.php". */
	private string $pluginFile;

	private string $slug;

	private string $storeUrl;

	private ?int $itemId;

	/** Currently installed plugin version, when the integration supplies it. */
	private ?string $currentVersion;

	private MinisignVerifier $verifier;

	private VerificationPolicy $policy;

	/** Verifies revocation manifests; null when revocation is not configured. */
	private ?MinisignVerifier $rootVerifier = null;

	/** Configured rollout mode for revocation checking, independent of $policy. */
	private VerificationPolicy $revocationPolicy;

	private RevocationList $revocations;

	/**
	 * Whether a revoked-key match should fail verification during the current
	 * interceptDownload() pass. Set per pass from the (filterable) revocation
	 * mode: in log mode a match is logged and the key stays effective, so the
	 * mechanism can soak before it is allowed to fail-close anything.
	 */
	private bool $revocationEnforcing = false;

	/** @var callable(): ?string Fetch the manifest-envelope body from the store. */
	private $revocationFetcher;

	/** @var callable(string $url): string|\WP_Error Download URL to local temp file. */
	private $downloader;

	/** @var callable(string $version): ?string Fetch .minisig text for a version. */
	private $signatureFetcher;

	/** @var callable(): ?object The plugin's row from the update_plugins transient. */
	private $updateResolver;

	/** @var callable(string $level, string $message): void */
	private $logger;

	/**
	 * @param array $args {
	 *     @type string   $plugin_file      Required. Plugin basename ("dir/file.php").
	 *     @type string   $slug             Required. Item slug as signed into releases.
	 *     @type string   $store_url        Required. EDD store URL.
	 *     @type string[] $public_keys      Required. minisign.pub file contents (or bare base64 lines).
	 *     @type int      $item_id          Optional. EDD download ID, passed to the signature endpoint.
	 *     @type string   $current_version  Required in enforce mode; strongly recommended otherwise.
	 *                                      The installed plugin version, used as the downgrade floor.
	 *                                      Omit it and a fresh install has NO floor until the first
	 *                                      verified update records a high-water mark — a compromised
	 *                                      store could walk that install up to any validly-signed
	 *                                      release at or above zero, including a known-vulnerable one,
	 *                                      before the ratchet engages. Because that floor is the whole
	 *                                      enforce-mode guarantee, constructing an enforce-mode guard
	 *                                      without it throws (register() then fails closed). Pass
	 *                                      `get_plugin_data( PLUGIN_FILE )['Version']` if you don't
	 *                                      already have the version handy.
	 *     @type string   $mode             Optional. off|log|enforce. Default log.
	 *     @type string   $revocation_root_key Optional. The pinned revocation root
	 *                                      public key (minisign.pub contents or bare
	 *                                      base64). Enables revocation checking.
	 *                                      Deliberately separate from public_keys:
	 *                                      the root signs only revocation manifests,
	 *                                      never packages, so a stolen root cannot
	 *                                      sign malware — it can only subtract trust.
	 *     @type string   $revocation_mode  Optional. off|log|enforce for revocation
	 *                                      checking specifically, independent of
	 *                                      $mode. Default log: a mechanism able to
	 *                                      fail-close the fleet gets its own
	 *                                      log-before-enforce rollout.
	 *     @type callable $downloader        Optional. Test/DI override.
	 *     @type callable $signature_fetcher Optional. Test/DI override.
	 *     @type callable $revocation_fetcher Optional. Test/DI override.
	 *     @type callable $update_resolver   Optional. Test/DI override.
	 *     @type callable $logger            Optional. Test/DI override.
	 * }
	 */
	public function __construct( array $args ) {
		foreach ( array( 'plugin_file', 'slug', 'store_url', 'public_keys' ) as $required ) {
			if ( empty( $args[ $required ] ) ) {
				throw new \InvalidArgumentException( "UpdaterGuard requires '{$required}'." );
			}
		}

		$this->pluginFile = $args['plugin_file'];
		$this->slug       = $args['slug'];
		$this->storeUrl   = $args['store_url'];
		$this->itemId     = isset( $args['item_id'] ) ? (int) $args['item_id'] : null;

		$current              = $args['current_version'] ?? null;
		$this->currentVersion = ( is_string( $current ) && '' !== $current ) ? $current : null;

		$keys = array();
		foreach ( (array) $args['public_keys'] as $key_text ) {
			$keys[] = self::parseKeyText( $key_text );
		}

		$this->revocationPolicy = new VerificationPolicy( $args['revocation_mode'] ?? VerificationPolicy::MODE_LOG );

		$root_key_text = $args['revocation_root_key'] ?? null;

		if ( is_string( $root_key_text ) && '' !== $root_key_text ) {
			// A separate verifier holding ONLY the root: a manifest signed by a
			// package key is rejected, and the root never verifies a package.
			// The root itself is not revocable — replacing a compromised root
			// is a normal release updating this pinned value.
			$root_key           = self::parseKeyText( $root_key_text );
			$this->rootVerifier = new MinisignVerifier( array( $root_key ) );

			// Scope the shared revocation cache to THIS root's full public key,
			// so a co-installed plugin pinning a different root can't poison
			// our trust set (cross-vendor DoS); same-shop guards pin the same
			// root and so share the same bucket, as designed.
			$this->revocations = new RevocationList( strtoupper( bin2hex( $root_key->raw() ) ) );

			$this->verifier = new MinisignVerifier(
				$keys,
				function ( string $key_id_hex ): bool {
					if ( ! $this->revocations->isRevoked( $key_id_hex ) ) {
						return false;
					}

					if ( $this->revocationEnforcing ) {
						return true;
					}

					// Log-only soak: record the match, keep the key effective.
					call_user_func(
						$this->logger,
						'warning',
						sprintf(
							'[signed-releases] %s: key %s is revoked; allowing anyway because revocation checking is in log mode (would block in enforce).',
							$this->slug,
							$key_id_hex
						)
					);

					return false;
				}
			);
		} else {
			// No pinned root: revocation is inert (isRevoked is never
			// consulted), so the default-scoped list is harmless.
			$this->revocations = new RevocationList();
			$this->verifier    = new MinisignVerifier( $keys );
		}

		$this->policy = new VerificationPolicy( $args['mode'] ?? VerificationPolicy::MODE_LOG );

		// The entire enforce-mode guarantee reduces to the downgrade floor,
		// and the installed version is its one input a compromised store
		// can't influence and a reset option can't erase. Configuring enforce
		// without it is a silent no-floor window on a fresh install — a
		// compromised store could walk the site up to any validly-signed
		// (possibly vulnerable) release before the ratchet engages. Treat it
		// as a hard misconfiguration: register() catches this and fails
		// closed (blocks this plugin's updates) rather than enforcing with no
		// floor. Runtime raises to enforce via the kill switch are caught in
		// interceptDownload() instead, where the effective mode is known.
		if ( $this->policy->shouldBlock() && null === $this->currentVersion ) {
			throw new \InvalidArgumentException(
				"UpdaterGuard requires 'current_version' in enforce mode: without the installed version there is no downgrade floor on a fresh install. Pass get_plugin_data( PLUGIN_FILE )['Version']."
			);
		}

		$this->downloader        = $args['downloader'] ?? array( $this, 'defaultDownloader' );
		$this->signatureFetcher  = $args['signature_fetcher'] ?? array( $this, 'defaultSignatureFetcher' );
		$this->revocationFetcher = $args['revocation_fetcher'] ?? array( $this, 'defaultRevocationFetcher' );
		$this->updateResolver    = $args['update_resolver'] ?? array( $this, 'defaultUpdateResolver' );
		$this->logger            = $args['logger'] ?? array( $this, 'defaultLogger' );
	}

	/**
	 * Parse a configured public key in either accepted form (full minisign.pub
	 * file text, or the bare base64 line).
	 */
	private static function parseKeyText( string $key_text ): PublicKey {
		return false !== strpos( $key_text, "\n" ) || 0 === strpos( $key_text, 'untrusted' )
			? PublicKey::fromFileText( $key_text )
			: PublicKey::fromBase64( $key_text );
	}

	/**
	 * Create and hook a guard in one call. The conventional entry point:
	 *
	 *     UpdaterGuard::register( array( ... ) );
	 *
	 * The README documents calling this directly inside add_action('init', ...)
	 * with no try/catch, so a bad key string or an invalid $args shape must
	 * never throw out of here — that would fatal every request on the site
	 * (WSOD), not just fail to verify updates. Fail closed instead: block
	 * this plugin's updates (when we at least know which plugin it is) and
	 * surface the problem in wp-admin, but keep the site serving requests.
	 *
	 * @return self|null The guard, or null if $args was misconfigured.
	 */
	public static function register( array $args ): ?self {
		try {
			$guard = new self( $args );
		} catch ( \Throwable $e ) {
			self::registerConfigFailure( is_string( $args['plugin_file'] ?? null ) ? $args['plugin_file'] : null, $e );

			return null;
		}

		$guard->hook();

		return $guard;
	}

	/**
	 * Best-effort fallback when construction itself fails: block updates for
	 * the plugin we at least know the identity of (fail closed rather than
	 * silently verifying nothing), and always report the problem somewhere
	 * an admin — and a log — will see it.
	 *
	 * @param string|null $plugin_file Plugin basename, if that much of $args was valid.
	 * @param \Throwable  $e           The construction failure.
	 */
	private static function registerConfigFailure( ?string $plugin_file, \Throwable $e ): void {
		if ( null !== $plugin_file && function_exists( 'add_filter' ) ) {
			add_filter(
				'upgrader_pre_download',
				static function ( $reply, $package, $upgrader = null, $hook_extra = array() ) use ( $plugin_file, $e ) {
					unset( $package, $upgrader );

					if ( ! is_array( $hook_extra ) || ( $hook_extra['plugin'] ?? null ) !== $plugin_file ) {
						return $reply;
					}

					return new \WP_Error(
						'pattonwebz_signed_releases_misconfigured',
						sprintf(
							/* translators: %s: underlying configuration error message */
							__( 'Update blocked: the release-signature verifier is misconfigured (%s). Fix the configuration, then retry the update.', 'pattonwebz-signed-releases' ),
							$e->getMessage()
						)
					);
				},
				10,
				4
			);
		}

		if ( function_exists( 'add_action' ) ) {
			add_action(
				'admin_notices',
				static function () use ( $e ) {
					if ( ! function_exists( 'current_user_can' ) || ! current_user_can( 'update_plugins' ) ) {
						return;
					}

					printf(
						'<div class="notice notice-error"><p><strong>%s</strong> %s</p></div>',
						esc_html__( 'Signed Releases verification misconfigured:', 'pattonwebz-signed-releases' ),
						esc_html( $e->getMessage() )
					);
				}
			);
		}

		if ( function_exists( 'error_log' ) ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- deliberate: this is the one path where hooking a logger callable isn't available (construction never completed).
			error_log( 'pattonwebz/signed-releases-client-for-edd: UpdaterGuard::register() failed: ' . $e->getMessage() );
		}
	}

	public function hook(): void {
		add_filter( 'upgrader_pre_download', array( $this, 'interceptDownload' ), 10, 4 );
		add_action( 'admin_notices', array( $this, 'renderFailureNotice' ) );
	}

	/**
	 * The upgrader_pre_download callback.
	 *
	 * @param mixed  $reply      false to let WP download; anything else short-circuits.
	 * @param string $package    Package URL.
	 * @param object $upgrader   WP_Upgrader instance (unused).
	 * @param array  $hook_extra Context; ['plugin'] carries the basename on plugin updates.
	 *
	 * @return mixed false (not ours), string verified file path, or \WP_Error.
	 */
	public function interceptDownload( $reply, $package, $upgrader = null, $hook_extra = array() ) {
		// The mode can be adjusted at runtime — the kill switch if a signing
		// mishap ever blocks legitimate updates before a fix ships. The
		// switch itself must not become the footgun: a typo'd override used
		// to fatal the upgrader (VerificationPolicy rejects unknown modes,
		// and strict_types rejects a non-string outright) — fall back to the
		// configured mode instead of throwing out of a live update.
		$mode = apply_filters( 'pattonwebz_signed_releases_mode', $this->policy->mode(), $this->slug );

		try {
			$policy = new VerificationPolicy( is_string( $mode ) ? $mode : '' );
		} catch ( \Throwable $e ) {
			$policy = $this->policy;

			call_user_func(
				$this->logger,
				'warning',
				sprintf(
					'[signed-releases] %s: pattonwebz_signed_releases_mode filter returned an invalid mode (%s); falling back to the configured mode (%s).',
					$this->slug,
					is_scalar( $mode ) ? (string) $mode : gettype( $mode ),
					$this->policy->mode()
				)
			);
		}

		// Not our plugin: never disturb another callback's reply. Checked
		// before the mode gate and independent of it — mode governs how we act
		// on our OWN plugin, never whether to touch another's.
		if ( ! is_array( $hook_extra )
			|| ( $hook_extra['plugin'] ?? null ) !== $this->pluginFile ) {
			return $reply;
		}

		// Refresh the revocation cache and fix this pass's revocation posture
		// FIRST, and independently of the main mode. Revocation is its own
		// log->enforce switch (README): revocation_mode=enforce must block a
		// stolen key even while package verification is still in log — or off
		// — mode, or the whole point of a separate revocation rollout is lost.
		// Runs before any signature is tried so a manifest revoking the
		// offering key applies to this very update. No-op (and no fetch) when
		// revocation isn't configured; failures inside are silent-safe.
		$this->prepareRevocations();

		// With the revocation posture known, decide whether there is anything
		// to do. Main mode off AND revocation not enforcing → nothing to
		// check; pass the reply through untouched. If revocation IS enforcing
		// we proceed even under main-off, precisely to catch a revoked key.
		if ( $policy->isOff() && ! $this->revocationEnforcing ) {
			return $reply;
		}

		// Enforce (main mode) with no installed-version floor is unsafe (see
		// the constructor). The constructor rejects a statically-configured
		// enforce mode without current_version; this covers the mode being
		// raised to enforce at runtime by the kill-switch filter, where the
		// constructor never saw it. Fail closed rather than enforce with no
		// downgrade floor. (Revocation-only enforcement under main-off/log
		// doesn't consult the floor, so this gate stays keyed to the main
		// policy.)
		if ( $policy->shouldBlock() && null === $this->currentVersion ) {
			call_user_func(
				$this->logger,
				'error',
				sprintf(
					'[signed-releases] %s: enforce mode active without current_version; blocking update (no downgrade floor).',
					$this->slug
				)
			);

			return new \WP_Error(
				'pattonwebz_signed_releases_no_floor',
				__( 'Update blocked: signature enforcement is on but the installed version was not supplied, so there is no downgrade floor. Pass current_version to the verifier.', 'pattonwebz-signed-releases' )
			);
		}

		// $reply may already be a file from an earlier upgrader_pre_download
		// callback. Verify THAT file rather than trusting it — otherwise a
		// mirror/cache (or a malicious) plugin hooking at the same priority
		// could slip an unverified package past enforcement. Only a false
		// reply means "download it yourself".
		$downloaded = false;

		if ( false !== $reply ) {
			if ( ! is_string( $reply ) || '' === $reply ) {
				return $reply; // WP_Error or unexpected type — pass through.
			}
			$file = $reply;
		} else {
			$file = call_user_func( $this->downloader, $package );

			if ( ! is_string( $file ) ) {
				return $file; // WP_Error from our own download.
			}
			$downloaded = true;
		}

		$update   = call_user_func( $this->updateResolver );
		$expected = isset( $update->new_version ) ? (string) $update->new_version : null;

		try {
			list( $comment, $signed_version ) = $this->verifyAgainstCandidates( $file, $update, $expected );
		} catch ( VerificationException $e ) {
			// A REVOKED_KEY failure is governed by the REVOCATION policy, not
			// the main one — and the verifier only ever throws it when
			// revocation is enforcing (log mode logs and lets the key stand),
			// so this failure always blocks regardless of the main mode. Every
			// other failure is governed by the main package-verification
			// policy as before.
			//
			// verifyAgainstCandidates() rethrows the FIRST candidate's failure,
			// so a REVOKED_KEY on a later candidate can be masked by an earlier
			// non-revoked failure — but only under main log/off, which already
			// fail open on any failure, so this concedes nothing an attacker
			// couldn't get anyway. The hard guarantee (a signature by a revoked
			// key never *verifies*) lives in MinisignVerifier and is
			// unconditional; this branch only governs how a failure is reported.
			$governing = VerificationException::REVOKED_KEY === $e->errorCode()
				? new VerificationPolicy( VerificationPolicy::MODE_ENFORCE )
				: $policy;

			return $this->handleFailure( $e, $governing, $package, $file, $downloaded );
		}

		if ( null !== $expected && '' !== $expected && $signed_version !== $expected ) {
			// A release replaced the file between this site's cached update
			// check and the download (one live version per download, replaced
			// in place). The delivered package verified as a genuinely newer
			// signed release, so accept it rather than strand the customer
			// until the update transient expires.
			call_user_func(
				$this->logger,
				'info',
				sprintf(
					'[signed-releases] %s: accepted signed version %s although the cached update offer said %s (release replaced in place between version check and download).',
					$this->slug,
					$signed_version,
					$expected
				)
			);
		}

		// Advance the downgrade ratchet only on a fully accepted release.
		$this->recordSeenVersion( (string) $signed_version );
		$this->clearFailures();

		/**
		 * Fires after a release package passed signature verification.
		 *
		 * @param string         $slug
		 * @param TrustedComment $comment
		 * @param string         $file
		 */
		do_action( 'pattonwebz_signed_releases_verified', $this->slug, $comment, $file );

		return $file;
	}

	/**
	 * Try each available signature until one fully verifies the file.
	 *
	 * Candidates, in order: the signature cached in the update transient,
	 * the endpoint's signature for the offered version, and finally the
	 * endpoint's *current* signature (empty version). The last one is what
	 * heals the release race: with one live version per download, a package
	 * downloaded moments after a release carries newer bytes than the
	 * transient's hours-old signature — only a fresh fetch can match it.
	 *
	 * Trying several store-supplied signatures concedes nothing: the store
	 * chooses what it serves either way, and every candidate must still pass
	 * the pinned-key crypto check, the slug binding, and the version rules.
	 *
	 * @param string      $file     Path to the downloaded package.
	 * @param object|null $update   The plugin's update_plugins row, if any.
	 * @param string|null $expected Store-offered new_version, if any.
	 *
	 * @return array{0: TrustedComment, 1: string} The authenticated comment and signed version.
	 *
	 * @throws VerificationException The first (most authoritative) failure when no candidate verifies.
	 */
	private function verifyAgainstCandidates( string $file, ?object $update, ?string $expected ): array {
		$first = null;
		$tried = array();

		foreach ( $this->signatureCandidates( $update, $expected ) as $minisig_text ) {
			if ( in_array( $minisig_text, $tried, true ) ) {
				continue;
			}
			$tried[] = $minisig_text;

			try {
				$signature = Signature::fromMinisigText( $minisig_text );
				$comment   = $this->verifier->verifyFile( $file, $signature );

				// Bind the authenticated slug to our configured slug
				// (cross-plugin replay defense). Slug only here — version is
				// checked off the authenticated comment, not $expected.
				$comment->assertMatches( $this->slug, null );

				$signed_version = $comment->get( 'version' );
				$this->assertSignedVersionAcceptable( $signed_version, $expected );

				return array( $comment, (string) $signed_version );
			} catch ( VerificationException $e ) {
				if ( null === $first ) {
					$first = $e;
				}
			}
		}

		throw null !== $first ? $first : VerificationException::withCode(
			VerificationException::MISSING_SIGNATURE,
			sprintf(
				'No signature available for %s %s from %s.',
				$this->slug,
				$expected ?? '(unknown version)',
				$this->storeUrl
			)
		);
	}

	/**
	 * Yield signature texts to try, lazily — later fetches only happen when
	 * earlier candidates failed.
	 *
	 * @param object|null $update   The plugin's update_plugins row, if any.
	 * @param string|null $expected Store-offered new_version, if any.
	 *
	 * @return \Generator<string>
	 *
	 * Candidate #1 (the transient's `signature` property) only exists if
	 * whatever EDD updater class populated `$update` copied the *entire*
	 * decoded API response onto the transient row rather than whitelisting
	 * known fields. Confirmed true for the classic `EDD_SL_Plugin_Updater`
	 * (it assigns the whole decoded object: `$_transient_data->response[$name]
	 * = $version_info;`), so the injected `signature` key survives there.
	 * Not independently confirmed for every `edd-sl-sdk`-based updater — if a
	 * newer SDK whitelists transient fields, this candidate is silently
	 * always absent. That's fine: candidates #2/#3 (fetched directly from the
	 * store's public signature endpoint below) don't depend on any updater
	 * internals and are what actually make verification work regardless of
	 * which EDD updater class the integrating plugin uses.
	 */
	private function signatureCandidates( ?object $update, ?string $expected ): \Generator {
		if ( isset( $update->signature ) && is_string( $update->signature ) && '' !== $update->signature ) {
			yield $update->signature;
		}

		if ( null !== $expected && '' !== $expected ) {
			$fetched = call_user_func( $this->signatureFetcher, $expected );

			if ( is_string( $fetched ) && '' !== $fetched ) {
				yield $fetched;
			}
		}

		// Last resort: the store's signature for whatever version is live
		// right now (the release-race healer).
		$current = call_user_func( $this->signatureFetcher, '' );

		if ( is_string( $current ) && '' !== $current ) {
			yield $current;
		}
	}

	/**
	 * Decide this pass's revocation posture and refresh the cached list.
	 *
	 * The revocation mode is filterable at runtime like the main mode (and
	 * with the same invalid-value fallback discipline): revocation is a
	 * mechanism that can fail-close the whole fleet, so it gets its own
	 * log-before-enforce rollout and its own kill switch, independent of
	 * whether package verification itself is enforcing.
	 */
	private function prepareRevocations(): void {
		$this->revocationEnforcing = false;

		if ( null === $this->rootVerifier ) {
			return; // No pinned root — the feature does not exist for this guard.
		}

		$mode = apply_filters( 'pattonwebz_signed_releases_revocation_mode', $this->revocationPolicy->mode(), $this->slug );

		try {
			$policy = new VerificationPolicy( is_string( $mode ) ? $mode : '' );
		} catch ( \Throwable $e ) {
			$policy = $this->revocationPolicy;

			call_user_func(
				$this->logger,
				'warning',
				sprintf(
					'[signed-releases] %s: pattonwebz_signed_releases_revocation_mode filter returned an invalid mode (%s); falling back to the configured mode (%s).',
					$this->slug,
					is_scalar( $mode ) ? (string) $mode : gettype( $mode ),
					$this->revocationPolicy->mode()
				)
			);
		}

		if ( $policy->isOff() ) {
			return;
		}

		$this->revocationEnforcing = $policy->shouldBlock();
		$this->refreshRevocations();
	}

	/**
	 * Fetch, root-verify, and merge the store's revocation manifest.
	 *
	 * Every failure path here is deliberately silent-safe (logged, never
	 * surfaced, never blocking): revocation state is monotonic, so keeping
	 * the existing cache and proceeding is exactly as correct as if the
	 * fetch had returned the same manifest again. Silence is only unsafe
	 * for claims that go stale — revocations never do.
	 */
	private function refreshRevocations(): void {
		try {
			$body = call_user_func( $this->revocationFetcher );

			if ( ! is_string( $body ) || '' === $body ) {
				call_user_func(
					$this->logger,
					'info',
					sprintf( '[signed-releases] %s: revocation manifest unavailable from the store; keeping the cached list.', $this->slug )
				);

				return;
			}

			$envelope = json_decode( $body, true, 4 );

			if ( ! is_array( $envelope )
				|| self::MANIFEST_ENVELOPE_FORMAT !== ( $envelope['format'] ?? null )
				|| ! is_string( $envelope['manifest'] ?? null )
				|| ! is_string( $envelope['minisig'] ?? null ) ) {
				call_user_func(
					$this->logger,
					'info',
					sprintf( '[signed-releases] %s: revocation manifest response was not a recognised envelope; keeping the cached list.', $this->slug )
				);

				return;
			}

			// Root signature first, over the exact manifest bytes; only then
			// parse. The store is an untrusted pipe — the pinned root is what
			// makes these bytes mean anything.
			$signature = Signature::fromMinisigText( $envelope['minisig'] );
			$comment   = $this->rootVerifier->verifyString( $envelope['manifest'], $signature );
			$manifest  = RevocationManifest::fromJson( $envelope['manifest'] );

			// The trusted comment mirrors the sequence for cheap sanity
			// checking; the signed JSON body is authoritative on any mismatch.
			$mirrored = $comment->get( 'sequence' );

			if ( null !== $mirrored && (string) $manifest->sequence() !== $mirrored ) {
				call_user_func(
					$this->logger,
					'warning',
					sprintf(
						'[signed-releases] %s: revocation manifest trusted-comment sequence (%s) disagrees with the signed body (%d); trusting the body.',
						$this->slug,
						$mirrored,
						$manifest->sequence()
					)
				);
			}

			$outcome = $this->revocations->apply( $manifest );

			if ( RevocationList::APPLY_ACCEPTED === $outcome ) {
				call_user_func(
					$this->logger,
					'info',
					sprintf(
						'[signed-releases] %s: accepted revocation manifest sequence %d (%d key(s) revoked).',
						$this->slug,
						$manifest->sequence(),
						count( $this->revocations->revokedKeys() )
					)
				);
			} elseif ( RevocationList::APPLY_ROLLBACK === $outcome ) {
				// A validly-root-signed but older manifest: a replay (or a
				// hostile store re-serving history). Never regress the cache.
				call_user_func(
					$this->logger,
					'warning',
					sprintf(
						'[signed-releases] %s: revocation_manifest_rollback — store served manifest sequence %d but this site has already accepted %d; ignoring it.',
						$this->slug,
						$manifest->sequence(),
						$this->revocations->sequence()
					)
				);
			}
		} catch ( \Throwable $e ) {
			call_user_func(
				$this->logger,
				'info',
				sprintf(
					'[signed-releases] %s: revocation manifest rejected (%s); keeping the cached list.',
					$this->slug,
					$e->getMessage()
				)
			);
		}
	}

	/**
	 * Enforce version binding off the *authenticated* signed version:
	 *  - it must be present (a signature with no version can't be bound);
	 *  - if the store also told us a version, the signed version must be that
	 *    version or a strictly newer one. Newer covers the release race (the
	 *    file was replaced between this site's cached version check and the
	 *    download) and concedes nothing: the store controls new_version, so a
	 *    malicious store could simply advertise the newer version honestly.
	 *    Older is the actual attack (pinning a site to a stale, still-validly-
	 *    signed release) and stays blocked;
	 *  - it must not be older than the highest version this site has already
	 *    verified, nor older than the installed version — the downgrade
	 *    ratchet that stops a compromised store rolling a site back to an
	 *    older, still-validly-signed (and possibly vulnerable) release.
	 *
	 * @param string|null $signed_version From the authenticated trusted comment.
	 * @param string|null $expected       Store-supplied new_version, if any.
	 *
	 * @throws VerificationException When the version is missing, older than offered, or a downgrade.
	 */
	private function assertSignedVersionAcceptable( ?string $signed_version, ?string $expected ): void {
		if ( null === $signed_version || '' === $signed_version ) {
			throw VerificationException::withCode(
				VerificationException::MISSING_VERSION,
				'Signature does not specify a version; cannot bind the release.'
			);
		}

		if ( null !== $expected && '' !== $expected && $signed_version !== $expected
			&& ! version_compare( $signed_version, $expected, '>' ) ) {
			throw VerificationException::withCode(
				VerificationException::COMMENT_MISMATCH,
				sprintf(
					'Signed version "%s" is neither the offered version "%s" nor a newer release.',
					$signed_version,
					$expected
				)
			);
		}

		$floor = $this->downgradeFloor();

		if ( null !== $floor && version_compare( $signed_version, $floor, '<' ) ) {
			throw VerificationException::withCode(
				VerificationException::DOWNGRADE,
				sprintf(
					'Refusing downgrade: signed version "%s" is older than "%s".',
					$signed_version,
					$floor
				)
			);
		}
	}

	/**
	 * The highest of the installed version and the ratchet high-water mark.
	 */
	private function downgradeFloor(): ?string {
		$floor = $this->highWaterVersion();

		if ( null !== $this->currentVersion
			&& ( null === $floor || version_compare( $this->currentVersion, $floor, '>' ) ) ) {
			$floor = $this->currentVersion;
		}

		return $floor;
	}

	private function highWaterVersion(): ?string {
		if ( ! function_exists( 'get_option' ) ) {
			return null;
		}

		$seen = get_option( self::OPTION_SEEN, array() );

		return isset( $seen[ $this->slug ] ) && is_string( $seen[ $this->slug ] )
			? $seen[ $this->slug ]
			: null;
	}

	private function recordSeenVersion( string $version ): void {
		if ( '' === $version || ! function_exists( 'get_option' ) || ! function_exists( 'update_option' ) ) {
			return;
		}

		$seen = get_option( self::OPTION_SEEN, array() );

		// A scalar here (another plugin, WP-CLI, a bad migration) would corrupt
		// the stored value or silently drop the ratchet write; start fresh instead.
		if ( ! is_array( $seen ) ) {
			$seen = array();
		}

		$current = ( isset( $seen[ $this->slug ] ) && is_string( $seen[ $this->slug ] ) ) ? $seen[ $this->slug ] : null;

		if ( null === $current || version_compare( $version, $current, '>' ) ) {
			$seen[ $this->slug ] = $version;
			update_option( self::OPTION_SEEN, $seen, false );
		}
	}

	/**
	 * @param string $file  Path to the package under inspection.
	 * @param bool   $owned Whether we downloaded $file (and may delete it).
	 *
	 * @return string|\WP_Error The package path (log mode) or an error (enforce mode).
	 */
	private function handleFailure( VerificationException $e, VerificationPolicy $policy, string $package, string $file, bool $owned ) {
		if ( $policy->shouldLog() ) {
			call_user_func(
				$this->logger,
				'error',
				sprintf(
					'[signed-releases] Verification failed for %s (%s): %s',
					$this->slug,
					$e->errorCode(),
					$e->getMessage()
				)
			);

			$this->recordFailure( $e );
		}

		/**
		 * Fires when a release package fails signature verification.
		 * Attach telemetry here (e.g. report to the store) if desired.
		 *
		 * @param string                $slug
		 * @param VerificationException $e
		 * @param string                $package
		 * @param bool                  $blocked
		 */
		do_action( 'pattonwebz_signed_releases_failure', $this->slug, $e, $package, $policy->shouldBlock() );

		if ( ! $policy->shouldBlock() ) {
			return $file; // Log-only rollout phase: allow the install.
		}

		// Only remove a file we downloaded ourselves; a path handed to us by
		// another callback is not ours to delete.
		if ( $owned ) {
			@unlink( $file );
		}

		return new \WP_Error(
			'signed_releases_verification_failed',
			sprintf(
				/* translators: 1: plugin slug, 2: failure detail. */
				'Update for "%1$s" was blocked: the package failed cryptographic signature verification (%2$s). The currently installed version has not been changed. Please contact support.',
				$this->slug,
				$e->getMessage()
			)
		);
	}

	private function recordFailure( VerificationException $e ): void {
		if ( ! function_exists( 'get_option' ) || ! function_exists( 'update_option' ) ) {
			return;
		}

		$failures = get_option( self::OPTION_FAILURES, array() );

		if ( ! is_array( $failures ) ) {
			$failures = array();
		}

		$failures[ $this->slug ] = array(
			'code'    => $e->errorCode(),
			'message' => $e->getMessage(),
			'time'    => time(),
		);

		update_option( self::OPTION_FAILURES, $failures, false );
	}

	private function clearFailures(): void {
		if ( ! function_exists( 'get_option' ) || ! function_exists( 'update_option' ) ) {
			return;
		}

		$failures = get_option( self::OPTION_FAILURES, array() );

		if ( isset( $failures[ $this->slug ] ) ) {
			unset( $failures[ $this->slug ] );
			update_option( self::OPTION_FAILURES, $failures, false );
		}
	}

	/**
	 * Deliberately not dismissible: a signature-verification failure means
	 * the installed release could not be authenticated, which stays true
	 * (and worth an admin's attention) until the next check actually
	 * succeeds and clearFailures() removes it — not until someone clicks
	 * away the notice.
	 */
	public function renderFailureNotice(): void {
		if ( ! current_user_can( 'update_plugins' ) ) {
			return;
		}

		$failures = get_option( self::OPTION_FAILURES, array() );
		$failure  = is_array( $failures ) ? ( $failures[ $this->slug ] ?? null ) : null;

		if ( ! is_array( $failure ) || ! isset( $failure['message'] ) || ! is_string( $failure['message'] ) ) {
			return;
		}

		printf(
			'<div class="notice notice-error"><p><strong>%s:</strong> %s</p></div>',
			esc_html( sprintf( 'Signature verification problem for %s', $this->slug ) ),
			esc_html( $failure['message'] )
		);
	}

	// Default WP-backed implementations, replaced by injected callables in tests.

	private function defaultDownloader( string $url ) {
		if ( ! function_exists( 'download_url' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		return download_url( $url );
	}

	private function defaultSignatureFetcher( string $version ): ?string {
		// add_query_arg() does NOT urlencode values; encode them ourselves so
		// e.g. a "+" in a semver build suffix survives ($_GET would otherwise
		// decode it to a space and the store's version lookup would miss).
		$args = array(
			'edd_action' => 'get_release_signature',
			'slug'       => rawurlencode( $this->slug ),
			'version'    => rawurlencode( $version ),
		);

		if ( null !== $this->itemId ) {
			$args['item_id'] = $this->itemId;
		}

		// The store is untrusted by design, so treat its responses accordingly:
		// wp_safe_remote_get() re-validates redirect targets, and the size cap
		// stops a hostile store feeding an unbounded body into memory (the
		// same attacker-forced-read class as the rejected legacy algorithm).
		$response = wp_safe_remote_get(
			add_query_arg( $args, $this->storeUrl ),
			array(
				'timeout'             => 15,
				'limit_response_size' => self::MAX_SIGNATURE_BYTES,
			)
		);

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}

		$body = wp_remote_retrieve_body( $response );

		return '' !== $body ? $body : null;
	}

	private function defaultRevocationFetcher(): ?string {
		// Store-wide, not per-product: one manifest covers every key the shop
		// signs with, so no slug/item_id parameters. Same untrusted-store
		// posture as the signature fetch: safe redirects and a hard size cap.
		$response = wp_safe_remote_get(
			add_query_arg( array( 'edd_action' => 'get_revocation_manifest' ), $this->storeUrl ),
			array(
				'timeout'             => 15,
				'limit_response_size' => self::MAX_MANIFEST_BYTES,
			)
		);

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}

		$body = wp_remote_retrieve_body( $response );

		return '' !== $body ? $body : null;
	}

	private function defaultUpdateResolver(): ?object {
		$transient = get_site_transient( 'update_plugins' );

		if ( ! is_object( $transient ) ) {
			return null; // get_site_transient() returns false when unset.
		}

		$row = $transient->response[ $this->pluginFile ] ?? null;

		return is_object( $row ) ? $row : null;
	}

	private function defaultLogger( string $level, string $message ): void {
		error_log( $message );
	}
}
