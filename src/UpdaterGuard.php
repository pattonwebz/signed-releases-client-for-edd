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
 */

declare(strict_types=1);

namespace PattonWebz\SignedReleases;

final class UpdaterGuard {

	/*
	 * COMPATIBILITY CONTRACT — this package ships un-prefixed in several
	 * plugins at once and the first-loaded copy serves them all. These
	 * option names, their slug-keyed array shapes, and the
	 * pattonwebz_signed_releases_{mode,verified,failure} hook signatures
	 * are frozen: changing any of them within a major version breaks
	 * co-installed plugins running another copy. See README.
	 */
	public const OPTION_FAILURES = 'pattonwebz_signed_releases_failures';

	/** Highest signed version verified per slug — the downgrade ratchet. */
	public const OPTION_SEEN = 'pattonwebz_signed_releases_seen';

	/** Plugin basename, e.g. "my-plugin/my-plugin.php". */
	private string $pluginFile;

	private string $slug;

	private string $storeUrl;

	private ?int $itemId;

	/** Currently installed plugin version, when the integration supplies it. */
	private ?string $currentVersion;

	private MinisignVerifier $verifier;

	private VerificationPolicy $policy;

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
	 *     @type string   $current_version  Optional. Installed plugin version; used as a downgrade floor.
	 *     @type string   $mode             Optional. off|log|enforce. Default log.
	 *     @type callable $downloader        Optional. Test/DI override.
	 *     @type callable $signature_fetcher Optional. Test/DI override.
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
			$keys[] = false !== strpos( $key_text, "\n" ) || 0 === strpos( $key_text, 'untrusted' )
				? PublicKey::fromFileText( $key_text )
				: PublicKey::fromBase64( $key_text );
		}
		$this->verifier = new MinisignVerifier( $keys );

		$this->policy = new VerificationPolicy( $args['mode'] ?? VerificationPolicy::MODE_LOG );

		$this->downloader       = $args['downloader'] ?? array( $this, 'defaultDownloader' );
		$this->signatureFetcher = $args['signature_fetcher'] ?? array( $this, 'defaultSignatureFetcher' );
		$this->updateResolver   = $args['update_resolver'] ?? array( $this, 'defaultUpdateResolver' );
		$this->logger           = $args['logger'] ?? array( $this, 'defaultLogger' );
	}

	/**
	 * Create and hook a guard in one call. The conventional entry point:
	 *
	 *     UpdaterGuard::register( array( ... ) );
	 */
	public static function register( array $args ): self {
		$guard = new self( $args );
		$guard->hook();

		return $guard;
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
		// mishap ever blocks legitimate updates before a fix ships.
		$mode   = apply_filters( 'pattonwebz_signed_releases_mode', $this->policy->mode(), $this->slug );
		$policy = new VerificationPolicy( $mode );

		// Not our plugin (or verification disabled): never disturb another
		// callback's reply.
		if ( $policy->isOff()
			|| ! is_array( $hook_extra )
			|| ( $hook_extra['plugin'] ?? null ) !== $this->pluginFile ) {
			return $reply;
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
			return $this->handleFailure( $e, $policy, $package, $file, $downloaded );
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

		$seen    = get_option( self::OPTION_SEEN, array() );
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
		$failure  = $failures[ $this->slug ] ?? null;

		if ( null === $failure ) {
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
		$args = array(
			'edd_action' => 'get_release_signature',
			'slug'       => $this->slug,
			'version'    => $version,
		);

		if ( null !== $this->itemId ) {
			$args['item_id'] = $this->itemId;
		}

		$response = wp_remote_get(
			add_query_arg( $args, $this->storeUrl ),
			array( 'timeout' => 15 )
		);

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}

		$body = wp_remote_retrieve_body( $response );

		return '' !== $body ? $body : null;
	}

	private function defaultUpdateResolver(): ?object {
		$transient = get_site_transient( 'update_plugins' );

		return $transient->response[ $this->pluginFile ] ?? null;
	}

	private function defaultLogger( string $level, string $message ): void {
		error_log( $message );
	}
}
