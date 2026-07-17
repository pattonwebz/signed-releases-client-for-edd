<?php

declare(strict_types=1);

namespace PattonWebz\SignedReleases\Tests;

use PattonWebz\SignedReleases\TrustedComment;
use PattonWebz\SignedReleases\UpdaterGuard;
use PattonWebz\SignedReleases\VerificationException;
use PattonWebz\SignedReleases\VerificationPolicy;
use PHPUnit\Framework\TestCase;

final class UpdaterGuardTest extends TestCase {

	use InTestSigner;

	private const PLUGIN_FILE = 'sample-plugin/sample-plugin.php';
	private const PACKAGE_URL = 'https://store.example/edd-sl/package_download/abc123';

	/** @var string[] Temp files to clean up. */
	private array $tempFiles = array();

	/** @var array<int, array{0: string, 1: string}> */
	private array $logged = array();

	protected function setUp(): void {
		wp_shims_reset();
		$this->logged = array();
	}

	protected function tearDown(): void {
		foreach ( $this->tempFiles as $file ) {
			if ( file_exists( $file ) ) {
				unlink( $file );
			}
		}
		$this->tempFiles = array();
	}

	private function fixture( string $name ): string {
		return PATTONWEBZ_TEST_FIXTURES . '/' . $name;
	}

	private function noVersionSignature(): string {
		return file_get_contents( $this->fixture( 'no-version.minisig' ) );
	}

	/**
	 * A downloader that "downloads" a fixture into a temp file, like
	 * download_url() would.
	 */
	private function downloaderFor( string $fixture_name ): callable {
		return function ( string $url ) use ( $fixture_name ): string {
			$tmp = tempnam( sys_get_temp_dir(), 'sig-test-' );
			copy( $this->fixture( $fixture_name ), $tmp );
			$this->tempFiles[] = $tmp;

			return $tmp;
		};
	}

	/**
	 * A downloader that writes arbitrary bytes to a temp file, for in-test
	 * signed payloads that have no fixture on disk.
	 */
	private function downloaderForData( string $data ): callable {
		return function ( string $url ) use ( $data ): string {
			$tmp = tempnam( sys_get_temp_dir(), 'sig-test-' );
			file_put_contents( $tmp, $data );
			$this->tempFiles[] = $tmp;

			return $tmp;
		};
	}

	private function makeGuardArgs( array $overrides = array() ): array {
		$defaults = array(
			'plugin_file'       => self::PLUGIN_FILE,
			'slug'              => 'sample-plugin',
			'store_url'         => 'https://store.example',
			'public_keys'       => array( file_get_contents( $this->fixture( 'testkey.pub' ) ) ),
			'mode'              => VerificationPolicy::MODE_ENFORCE,
			// Enforce mode now requires an installed-version floor. A minimal
			// value keeps it inert for tests not about the downgrade floor;
			// floor/no-floor cases override or unset it explicitly.
			'current_version'   => '0.0.1',
			'downloader'        => $this->downloaderFor( 'sample-plugin-1.2.3.zip' ),
			'signature_fetcher' => function ( string $version ): ?string {
				return file_get_contents( $this->fixture( 'sample-plugin-1.2.3.zip.minisig' ) );
			},
			'update_resolver'   => static function (): object {
				return (object) array( 'new_version' => '1.2.3' );
			},
			'logger'            => function ( string $level, string $message ): void {
				$this->logged[] = array( $level, $message );
			},
		);

		return array_merge( $defaults, $overrides );
	}

	private function makeGuard( array $overrides = array() ): UpdaterGuard {
		return new UpdaterGuard( $this->makeGuardArgs( $overrides ) );
	}

	private function intercept( UpdaterGuard $guard, array $hook_extra = array( 'plugin' => self::PLUGIN_FILE ) ) {
		return $guard->interceptDownload( false, self::PACKAGE_URL, null, $hook_extra );
	}

	private function firedActions(): array {
		return array_column( $GLOBALS['__wp_actions'], 'tag' );
	}

	/** Arguments the first firing of $tag received, or null when never fired. */
	private function firedActionArgs( string $tag ): ?array {
		foreach ( $GLOBALS['__wp_actions'] as $action ) {
			if ( $tag === $action['tag'] ) {
				return $action['args'];
			}
		}

		return null;
	}

	public function testValidPackagePassesAndReturnsVerifiedFile(): void {
		$result = $this->intercept( $this->makeGuard() );

		$this->assertIsString( $result );
		$this->assertFileExists( $result );
		$this->assertContains( 'pattonwebz_signed_releases_verified', $this->firedActions() );
		$this->assertSame( array(), $this->logged );
	}

	public function testIgnoresOtherPlugins(): void {
		$guard = $this->makeGuard(
			array(
				'downloader' => static function (): string {
					throw new \LogicException( 'Downloader must not run for other plugins.' );
				},
			)
		);

		$this->assertFalse( $this->intercept( $guard, array( 'plugin' => 'other/other.php' ) ) );
		$this->assertFalse( $this->intercept( $guard, array() ) );
	}

	public function testWpErrorReplyPassesThrough(): void {
		$guard = $this->makeGuard();
		$error = new \WP_Error( 'download_failed', 'nope' );

		$this->assertSame(
			$error,
			$guard->interceptDownload( $error, self::PACKAGE_URL, null, array( 'plugin' => self::PLUGIN_FILE ) )
		);
	}

	public function testVerifiesAFileSuppliedByAnEarlierCallback(): void {
		// Another upgrader_pre_download callback already produced a file path.
		// We must verify THAT file, not blindly trust it.
		$tmp = tempnam( sys_get_temp_dir(), 'sig-test-' );
		copy( $this->fixture( 'sample-plugin-1.2.3.zip' ), $tmp );
		$this->tempFiles[] = $tmp;

		$guard = $this->makeGuard(
			array(
				'downloader' => static function (): string {
					throw new \LogicException( 'Must not download when a reply file is supplied.' );
				},
			)
		);

		$result = $guard->interceptDownload( $tmp, self::PACKAGE_URL, null, array( 'plugin' => self::PLUGIN_FILE ) );

		$this->assertSame( $tmp, $result );
		$this->assertContains( 'pattonwebz_signed_releases_verified', $this->firedActions() );
	}

	public function testBlocksAnUnverifiableFileSuppliedByAnEarlierCallback(): void {
		// A mirror/cache (or malicious) plugin slips in a tampered file.
		$tmp = tempnam( sys_get_temp_dir(), 'sig-test-' );
		copy( $this->fixture( 'sample-plugin-1.2.3.tampered.zip' ), $tmp );
		$this->tempFiles[] = $tmp;

		$guard  = $this->makeGuard();
		$result = $guard->interceptDownload( $tmp, self::PACKAGE_URL, null, array( 'plugin' => self::PLUGIN_FILE ) );

		$this->assertInstanceOf( \WP_Error::class, $result );
		// We must not delete a file another callback owns.
		$this->assertFileExists( $tmp );
	}

	public function testOffModeReturnsReplyUntouched(): void {
		$guard = $this->makeGuard( array( 'mode' => VerificationPolicy::MODE_OFF ) );

		$this->assertFalse( $this->intercept( $guard ) );
		$this->assertSame( 'x', $guard->interceptDownload( 'x', self::PACKAGE_URL, null, array( 'plugin' => self::PLUGIN_FILE ) ) );
	}

	public function testModeFilterActsAsKillSwitch(): void {
		$GLOBALS['__wp_filter_overrides']['pattonwebz_signed_releases_mode'] = VerificationPolicy::MODE_OFF;

		$this->assertFalse( $this->intercept( $this->makeGuard() ) );
	}

	public function testInvalidModeFilterFallsBackInsteadOfFatal(): void {
		// A typo'd override used to throw uncaught out of a live upgrader
		// call - the kill switch becoming the footgun. It must instead fall
		// back to the configured (enforce) mode and keep blocking as normal.
		$GLOBALS['__wp_filter_overrides']['pattonwebz_signed_releases_mode'] = 'enforcee';

		$guard  = $this->makeGuard( array( 'downloader' => $this->downloaderFor( 'sample-plugin-1.2.3.tampered.zip' ) ) );
		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result, 'Falls back to enforce, so a bad package is still blocked.' );
		$this->assertNotEmpty( $this->logged );
		$this->assertSame( 'warning', $this->logged[0][0] );
		$this->assertStringContainsString( 'invalid mode', $this->logged[0][1] );
	}

	public function testNonStringModeFilterFallsBackInsteadOfFatal(): void {
		// A non-string filter return is normalised to '' before it reaches
		// VerificationPolicy, whose constructor rejects '' with an
		// InvalidArgumentException — caught the same as any bad string.
		$GLOBALS['__wp_filter_overrides']['pattonwebz_signed_releases_mode'] = array( 'enforce' );

		$result = $this->intercept( $this->makeGuard() );

		$this->assertIsString( $result, 'Falls back to the configured mode and verifies normally rather than fataling.' );
		$this->assertNotEmpty( $this->logged );
		$this->assertSame( 'warning', $this->logged[0][0] );
	}

	public function testDownloadErrorPassesThrough(): void {
		$error = new \WP_Error( 'http_404', 'Not found' );
		$guard = $this->makeGuard(
			array(
				'downloader' => static function () use ( $error ) {
					return $error;
				},
			)
		);

		$this->assertSame( $error, $this->intercept( $guard ) );
	}

	public function testTamperedPackageBlockedInEnforceMode(): void {
		$guard  = $this->makeGuard( array( 'downloader' => $this->downloaderFor( 'sample-plugin-1.2.3.tampered.zip' ) ) );
		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( 'signed_releases_verification_failed', $result->get_error_code() );
		$this->assertFileDoesNotExist( $this->tempFiles[0] );
		$this->assertContains( 'pattonwebz_signed_releases_failure', $this->firedActions() );
		$this->assertNotEmpty( $this->logged );
	}

	public function testTamperedPackageAllowedButLoggedInLogMode(): void {
		$guard = $this->makeGuard(
			array(
				'mode'       => VerificationPolicy::MODE_LOG,
				'downloader' => $this->downloaderFor( 'sample-plugin-1.2.3.tampered.zip' ),
			)
		);

		$result = $this->intercept( $guard );

		$this->assertIsString( $result );
		$this->assertFileExists( $result );
		$this->assertNotEmpty( $this->logged );
		$this->assertContains( 'pattonwebz_signed_releases_failure', $this->firedActions() );

		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertSame( 'bad_signature', $failures['sample-plugin']['code'] );
	}

	public function testMissingSignatureIsAFailure(): void {
		$guard = $this->makeGuard(
			array(
				'signature_fetcher' => static function (): ?string {
					return null;
				},
			)
		);

		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );
		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertSame( 'missing_signature', $failures['sample-plugin']['code'] );

		// The recorded message must give an admin everything needed to chase
		// the problem: which plugin, which version, which store.
		$this->assertStringContainsString( 'sample-plugin', $failures['sample-plugin']['message'] );
		$this->assertStringContainsString( '1.2.3', $failures['sample-plugin']['message'] );
		$this->assertStringContainsString( 'https://store.example', $failures['sample-plugin']['message'] );
	}

	public function testSignatureFromTransientIsPreferredOverFetch(): void {
		$guard = $this->makeGuard(
			array(
				'update_resolver'   => function (): object {
					return (object) array(
						'new_version' => '1.2.3',
						'signature'   => file_get_contents( $this->fixture( 'sample-plugin-1.2.3.zip.minisig' ) ),
					);
				},
				'signature_fetcher' => static function (): ?string {
					throw new \LogicException( 'Fetcher must not run when the transient has the signature.' );
				},
			)
		);

		$this->assertIsString( $this->intercept( $guard ) );
	}

	public function testVersionMismatchBlocked(): void {
		// Store claims 1.2.4 but the signature covers 1.2.3 — replay of an
		// old-but-validly-signed package must not pass as the new version.
		$guard = $this->makeGuard(
			array(
				'update_resolver' => static function (): object {
					return (object) array( 'new_version' => '1.2.4' );
				},
			)
		);

		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );
		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertSame( 'comment_mismatch', $failures['sample-plugin']['code'] );
	}

	public function testAbsentNewVersionStillBindsOffSignedVersion(): void {
		// HIGH-1: a compromised store omits new_version to try to skip the
		// version check. We bind off the authenticated signed version instead,
		// so verification still completes (and the ratchet still applies).
		$guard = $this->makeGuard(
			array(
				'update_resolver' => function (): object {
					return (object) array(
						'signature' => file_get_contents( $this->fixture( 'sample-plugin-1.2.3.zip.minisig' ) ),
					);
				},
			)
		);

		$this->assertIsString( $this->intercept( $guard ) );
	}

	/**
	 * A genuinely stale transient signature: made by a trusted key, but over
	 * the previous release's bytes — exactly what the transient holds after
	 * the store replaced the package in place. Fails BAD_SIGNATURE against
	 * the delivered file.
	 *
	 * @return array{0: string, 1: string} Stale minisig text, trusted public key (bare base64).
	 */
	private function staleTrustedSignature(): array {
		$keypair = $this->makeSignerKeypair();
		$stale   = $this->signMinisig(
			$keypair,
			'bytes of the replaced 1.2.2 package, not the file being delivered',
			'slug:sample-plugin version:1.2.2 signed:2026-07-14T00:00:00Z'
		);

		return array( $stale, $keypair['public_b64'] );
	}

	public function testReleaseRaceHealedByFreshCurrentSignature(): void {
		// The store has one live version per download, replaced in place. This
		// site cached "1.2.2 available" (with 1.2.2's signature) hours ago;
		// 1.2.3 shipped since, so the download delivers 1.2.3 bytes that the
		// cached signature cannot verify (bad_signature). The guard must fall
		// through to the endpoint's *current* signature and accept the newer
		// release instead of stranding the customer until the transient expires.
		$fetches = array();

		list( $stale_sig, $stale_pub ) = $this->staleTrustedSignature();

		$guard = $this->makeGuard(
			array(
				'public_keys'       => array(
					file_get_contents( $this->fixture( 'testkey.pub' ) ),
					$stale_pub,
				),
				'update_resolver'   => static function () use ( $stale_sig ): object {
					return (object) array(
						'new_version' => '1.2.2',
						'signature'   => $stale_sig,
					);
				},
				'signature_fetcher' => function ( string $version ) use ( &$fetches ): ?string {
					$fetches[] = $version;

					// The offered version's signature is gone with the old file;
					// only the current ('') signature is useful.
					return '' === $version
						? file_get_contents( $this->fixture( 'sample-plugin-1.2.3.zip.minisig' ) )
						: null;
				},
			)
		);

		$result = $this->intercept( $guard );

		$this->assertIsString( $result, 'Race must heal, not block.' );
		$this->assertSame( array( '1.2.2', '' ), $fetches, 'Current-signature fetch is the last resort.' );
		$this->assertSame( '1.2.3', get_option( UpdaterGuard::OPTION_SEEN )['sample-plugin'] );
		$this->assertNotSame( array(), $this->logged, 'Accepting a newer-than-offered release is logged.' );
		$this->assertStringContainsString( 'replaced in place', $this->logged[0][1] );
	}

	public function testNewerSignedVersionAcceptedOverStaleOffer(): void {
		// Version binding accepts strictly newer: the store controls
		// new_version, so blocking newer would only punish the race, not an
		// attacker (who would simply advertise the newer version honestly).
		$guard = $this->makeGuard(
			array(
				'downloader'        => $this->downloaderFor( 'sample-plugin-1.2.3.zip' ),
				'signature_fetcher' => function (): ?string {
					return file_get_contents( $this->fixture( 'version-mismatch.minisig' ) ); // Signs these bytes as 9.9.9.
				},
			)
		);

		$this->assertIsString( $this->intercept( $guard ) );
		$this->assertSame( '9.9.9', get_option( UpdaterGuard::OPTION_SEEN )['sample-plugin'] );
	}

	public function testRaceHealerCannotRescueADowngrade(): void {
		// The fresh-current-signature fallback still sits behind the ratchet:
		// a "current" release older than what this site has already verified
		// stays blocked, race or no race.
		update_option( UpdaterGuard::OPTION_SEEN, array( 'sample-plugin' => '2.0.0' ) );

		list( $stale_sig, $stale_pub ) = $this->staleTrustedSignature();

		$guard = $this->makeGuard(
			array(
				'public_keys'       => array(
					file_get_contents( $this->fixture( 'testkey.pub' ) ),
					$stale_pub,
				),
				'update_resolver'   => static function () use ( $stale_sig ): object {
					return (object) array(
						'new_version' => '1.2.2',
						'signature'   => $stale_sig,
					);
				},
				'signature_fetcher' => function ( string $version ): ?string {
					return '' === $version
						? file_get_contents( $this->fixture( 'sample-plugin-1.2.3.zip.minisig' ) )
						: null;
				},
			)
		);

		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( '2.0.0', get_option( UpdaterGuard::OPTION_SEEN )['sample-plugin'], 'Ratchet must not move on a blocked install.' );

		// verifyAgainstCandidates() surfaces the FIRST failure as the most
		// authoritative one: here that is the stale transient signature
		// failing over the delivered bytes, not the healer's later downgrade
		// rejection. (First-candidate-wins is pinned directly in
		// testFirstCandidateFailureCodeIsTheOneRecorded.)
		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertSame( 'bad_signature', $failures['sample-plugin']['code'] );
	}

	public function testDowngradeBelowSeenVersionBlocked(): void {
		// HIGH-2: the site has already verified 2.0.0; a compromised store
		// offers a genuinely-signed older 1.2.3 to roll the site back.
		update_option( UpdaterGuard::OPTION_SEEN, array( 'sample-plugin' => '2.0.0' ) );

		$guard  = $this->makeGuard();
		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );
		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertSame( 'downgrade', $failures['sample-plugin']['code'] );
	}

	public function testDowngradeBelowInstalledVersionBlocked(): void {
		// The installed version is a floor even before anything is recorded.
		$guard  = $this->makeGuard( array( 'current_version' => '3.1.0' ) );
		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );
		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertSame( 'downgrade', $failures['sample-plugin']['code'] );
	}

	public function testSuccessAdvancesTheDowngradeRatchet(): void {
		$this->assertIsString( $this->intercept( $this->makeGuard() ) );

		$seen = get_option( UpdaterGuard::OPTION_SEEN );
		$this->assertSame( '1.2.3', $seen['sample-plugin'] );
	}

	public function testEqualVersionReverifySucceedsAndKeepsRatchet(): void {
		// A version equal to the high-water mark is not a downgrade: a
		// reinstall of the current release must verify, and must not lower
		// (or need to move) the recorded mark.
		update_option( UpdaterGuard::OPTION_SEEN, array( 'sample-plugin' => '1.2.3' ) );

		$this->assertIsString( $this->intercept( $this->makeGuard() ) );
		$this->assertSame( '1.2.3', get_option( UpdaterGuard::OPTION_SEEN )['sample-plugin'] );
	}

	public function testSignatureWithoutVersionTokenBlocked(): void {
		// A signature whose trusted comment carries no version: cannot be bound.
		$guard = $this->makeGuard(
			array(
				'update_resolver'   => static function (): object {
					return (object) array( 'new_version' => '1.2.3' );
				},
				'signature_fetcher' => function (): ?string {
					return $this->noVersionSignature();
				},
			)
		);

		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );
		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertSame( 'missing_version', $failures['sample-plugin']['code'] );
	}

	public function testSuccessClearsPreviousFailureRecord(): void {
		update_option(
			UpdaterGuard::OPTION_FAILURES,
			array( 'sample-plugin' => array( 'code' => 'bad_signature', 'message' => 'old', 'time' => 1 ) )
		);

		$this->intercept( $this->makeGuard() );

		$this->assertArrayNotHasKey( 'sample-plugin', get_option( UpdaterGuard::OPTION_FAILURES ) );
	}

	public function testFailureNoticeRendersForAdmins(): void {
		$guard = $this->makeGuard( array( 'mode' => VerificationPolicy::MODE_LOG, 'downloader' => $this->downloaderFor( 'sample-plugin-1.2.3.tampered.zip' ) ) );
		$this->intercept( $guard );

		ob_start();
		$guard->renderFailureNotice();
		$html = ob_get_clean();

		$this->assertStringContainsString( 'notice-error', $html );
		$this->assertStringContainsString( 'sample-plugin', $html );

		$GLOBALS['__wp_user_can'] = false;
		ob_start();
		$guard->renderFailureNotice();
		$this->assertSame( '', ob_get_clean() );
	}

	public function testRegisterHooksFilters(): void {
		$guard = UpdaterGuard::register(
			array(
				'plugin_file' => self::PLUGIN_FILE,
				'slug'        => 'sample-plugin',
				'store_url'   => 'https://store.example',
				'public_keys' => array( file_get_contents( $this->fixture( 'testkey.pub' ) ) ),
			)
		);

		$tags = array_column( $GLOBALS['__wp_hooks'], 'tag' );

		$this->assertContains( 'upgrader_pre_download', $tags );
		$this->assertContains( 'admin_notices', $tags );

		// accepted_args MUST be 4: with the WordPress default of 1 the
		// $hook_extra context never arrives, every download looks like
		// "not our plugin", and verification silently never runs.
		$hook = $this->lastHookFor( 'upgrader_pre_download' );
		$this->assertSame( 10, $hook['priority'] );
		$this->assertSame( 4, $hook['accepted_args'] );
	}

	public function testDispatchThroughRegisteredHookVerifiesThePackage(): void {
		// Exercise the wiring itself: call the recorded callback the way
		// WordPress would — with exactly the accepted_args number of
		// arguments the hook was registered with. If registration ever
		// under-declares accepted_args, $hook_extra goes missing here and
		// the guard degrades to a silent no-op (returns false, no verify).
		UpdaterGuard::register( $this->makeGuardArgs() );

		$hook = $this->lastHookFor( 'upgrader_pre_download' );
		$this->assertNotNull( $hook );

		$wp_args = array( false, self::PACKAGE_URL, new \stdClass(), array( 'plugin' => self::PLUGIN_FILE ) );
		$result  = call_user_func_array( $hook['callback'], array_slice( $wp_args, 0, $hook['accepted_args'] ) );

		$this->assertIsString( $result, 'Dispatching with the registered accepted_args must reach verification.' );
		$this->assertContains( 'pattonwebz_signed_releases_verified', $this->firedActions() );
	}

	/** Last full hook record registered for a tag, or null. */
	private function lastHookFor( string $tag ): ?array {
		$found = null;

		foreach ( $GLOBALS['__wp_hooks'] as $hook ) {
			if ( $hook['tag'] === $tag ) {
				$found = $hook;
			}
		}

		return $found;
	}

	/** Last hook callback registered for a tag, or null. */
	private function lastCallbackFor( string $tag ): ?callable {
		$hook = $this->lastHookFor( $tag );

		return null !== $hook ? $hook['callback'] : null;
	}

	public function testRegisterReturnsNullAndBlocksThatPluginOnBadPublicKey(): void {
		$guard = UpdaterGuard::register(
			array(
				'plugin_file' => self::PLUGIN_FILE,
				'slug'        => 'sample-plugin',
				'store_url'   => 'https://store.example',
				'public_keys' => array( 'not a valid minisign public key' ),
			)
		);

		$this->assertNull( $guard, 'A construction failure must not throw out of register().' );

		$blocker = $this->lastCallbackFor( 'upgrader_pre_download' );
		$this->assertNotNull( $blocker );

		$result = $blocker( false, self::PACKAGE_URL, null, array( 'plugin' => self::PLUGIN_FILE ) );
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( 'pattonwebz_signed_releases_misconfigured', $result->get_error_code() );

		// A different plugin's update must be completely unaffected.
		$this->assertFalse( $blocker( false, self::PACKAGE_URL, null, array( 'plugin' => 'other/other.php' ) ) );

		// A malformed $hook_extra must pass the reply through, not fatal.
		$this->assertFalse( $blocker( false, self::PACKAGE_URL, null, 'not-an-array' ) );
		$this->assertSame( 'earlier-reply', $blocker( 'earlier-reply', self::PACKAGE_URL, null, 'not-an-array' ) );
	}

	public function testRegisterConfigFailureShowsAdminNotice(): void {
		UpdaterGuard::register(
			array(
				'plugin_file' => self::PLUGIN_FILE,
				'slug'        => 'sample-plugin',
				'store_url'   => 'https://store.example',
				'public_keys' => array( 'not a valid minisign public key' ),
			)
		);

		$notice = $this->lastCallbackFor( 'admin_notices' );
		$this->assertNotNull( $notice );

		ob_start();
		$notice();
		$html = ob_get_clean();

		$this->assertStringContainsString( 'notice-error', $html );
		$this->assertStringContainsString( 'misconfigured', $html );

		$GLOBALS['__wp_user_can'] = false;
		ob_start();
		$notice();
		$this->assertSame( '', ob_get_clean(), 'Must respect the update_plugins capability like the regular failure notice.' );
	}

	public function testRegisterReturnsNullWithoutBlockingWhenPluginFileItselfIsMissing(): void {
		// Without even a valid plugin_file we can't identify which plugin's
		// updates to block — best effort is limited to the admin notice/log.
		$guard = UpdaterGuard::register(
			array(
				'slug'        => 'sample-plugin',
				'store_url'   => 'https://store.example',
				'public_keys' => array( file_get_contents( $this->fixture( 'testkey.pub' ) ) ),
			)
		);

		$this->assertNull( $guard );
		$this->assertNull( $this->lastCallbackFor( 'upgrader_pre_download' ) );
		$this->assertNotNull( $this->lastCallbackFor( 'admin_notices' ) );
	}

	public function testAcceptsBareBase64PublicKey(): void {
		$lines = array_values(
			array_filter( array_map( 'trim', file( $this->fixture( 'testkey.pub' ) ) ) )
		);

		$guard = $this->makeGuard( array( 'public_keys' => array( $lines[1] ) ) );

		$this->assertIsString( $this->intercept( $guard ) );
	}

	public function testSlugReplayBlockedAtGuardLevel(): void {
		// Cross-plugin replay: a genuinely-signed package for another plugin
		// (slug:evil-plugin in the authenticated comment) is served for ours.
		// The crypto verifies; the slug binding must still block it.
		$guard = $this->makeGuard(
			array(
				'signature_fetcher' => function (): ?string {
					return file_get_contents( $this->fixture( 'slug-mismatch.minisig' ) );
				},
			)
		);

		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );

		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertSame( 'comment_mismatch', $failures['sample-plugin']['code'] );
		$this->assertStringContainsString( 'evil-plugin', $failures['sample-plugin']['message'] );
		$this->assertStringContainsString( 'sample-plugin', $failures['sample-plugin']['message'] );
	}

	public function testDowngradeComparisonIsNumericNotLexicographic(): void {
		// '1.2.3' sorts AFTER '1.2.10' as a string; only version_compare()
		// treats 1.2.10 as the newer release. A lexicographic floor would
		// wave this downgrade straight through.
		$guard  = $this->makeGuard( array( 'current_version' => '1.2.10' ) );
		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );

		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertSame( 'downgrade', $failures['sample-plugin']['code'] );

		// The message names both versions so an admin can see what happened.
		$this->assertStringContainsString( '1.2.3', $failures['sample-plugin']['message'] );
		$this->assertStringContainsString( '1.2.10', $failures['sample-plugin']['message'] );
	}

	public function downgradeFloorProvider(): array {
		return array(
			'seen version is the floor'      => array( '2.0.0', '1.0.0' ),
			'installed version is the floor' => array( '1.0.0', '2.0.0' ),
		);
	}

	/**
	 * The floor is the MAX of the ratchet high-water mark and the installed
	 * version — whichever branch supplies the higher value must block.
	 *
	 * @dataProvider downgradeFloorProvider
	 */
	public function testDowngradeFloorIsMaxOfSeenAndInstalled( string $seen, string $current ): void {
		update_option( UpdaterGuard::OPTION_SEEN, array( 'sample-plugin' => $seen ) );

		$guard  = $this->makeGuard( array( 'current_version' => $current ) );
		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );

		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertSame( 'downgrade', $failures['sample-plugin']['code'] );
	}

	public function testSuccessIsScopedToOwnSlugInOptions(): void {
		// Another co-installed plugin's records live in the same shared
		// options; a success for our slug must not disturb them.
		update_option( UpdaterGuard::OPTION_SEEN, array( 'other-plugin' => '9.9.9' ) );
		update_option(
			UpdaterGuard::OPTION_FAILURES,
			array(
				'other-plugin'  => array( 'code' => 'bad_signature', 'message' => 'theirs', 'time' => 1 ),
				'sample-plugin' => array( 'code' => 'bad_signature', 'message' => 'ours', 'time' => 2 ),
			)
		);

		$this->assertIsString( $this->intercept( $this->makeGuard() ) );

		$seen = get_option( UpdaterGuard::OPTION_SEEN );
		$this->assertSame( '9.9.9', $seen['other-plugin'] );
		$this->assertSame( '1.2.3', $seen['sample-plugin'] );

		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertArrayNotHasKey( 'sample-plugin', $failures, 'Own failure record is cleared.' );
		$this->assertSame( 'theirs', $failures['other-plugin']['message'], 'Other slug untouched.' );
	}

	public function testFailureRecordShapeAndSlugScoping(): void {
		update_option(
			UpdaterGuard::OPTION_FAILURES,
			array( 'other-plugin' => array( 'code' => 'downgrade', 'message' => 'theirs', 'time' => 1 ) )
		);

		$guard = $this->makeGuard( array( 'downloader' => $this->downloaderFor( 'sample-plugin-1.2.3.tampered.zip' ) ) );
		$this->intercept( $guard );

		$failures = get_option( UpdaterGuard::OPTION_FAILURES );

		// Frozen record shape (compatibility contract with co-installed copies).
		$this->assertSame( array( 'code', 'message', 'time' ), array_keys( $failures['sample-plugin'] ) );
		$this->assertSame( 'bad_signature', $failures['sample-plugin']['code'] );
		$this->assertIsString( $failures['sample-plugin']['message'] );
		$this->assertIsInt( $failures['sample-plugin']['time'] );

		$this->assertSame( 'theirs', $failures['other-plugin']['message'], 'Other slug untouched by our failure.' );
	}

	public function testFailureNoticeEscapesHtmlInMessage(): void {
		update_option(
			UpdaterGuard::OPTION_FAILURES,
			array(
				'sample-plugin' => array(
					'code'    => 'bad_signature',
					'message' => '<script>alert(1)</script>',
					'time'    => 1,
				),
			)
		);

		$guard = $this->makeGuard();

		ob_start();
		$guard->renderFailureNotice();
		$html = ob_get_clean();

		$this->assertStringContainsString( '&lt;script&gt;', $html );
		$this->assertStringNotContainsString( '<script>', $html );
	}

	public function nonRenderableFailureProvider(): array {
		return array(
			'no entry for slug'      => array( array() ),
			'entry is a string'      => array( array( 'sample-plugin' => 'just a string' ) ),
			'entry missing message'  => array( array( 'sample-plugin' => array( 'code' => 'bad_signature', 'time' => 1 ) ) ),
			'message is not string'  => array( array( 'sample-plugin' => array( 'code' => 'x', 'message' => 42, 'time' => 1 ) ) ),
		);
	}

	/**
	 * @dataProvider nonRenderableFailureProvider
	 */
	public function testFailureNoticeSilentWithoutRenderableEntry( array $failures ): void {
		update_option( UpdaterGuard::OPTION_FAILURES, $failures );

		ob_start();
		$this->makeGuard()->renderFailureNotice();

		$this->assertSame( '', ob_get_clean() );
	}

	public function testDefaultSignatureFetcherBuildsTheEndpointRequest(): void {
		// signature_fetcher => null falls through to defaultSignatureFetcher().
		// No responses are queued, so both fetches fail (WP_Error) — this test
		// is about the request shape, which the shim records.
		$guard = $this->makeGuard(
			array(
				'slug'              => 'weird+slug',
				'item_id'           => 42,
				'signature_fetcher' => null,
				'update_resolver'   => static function (): object {
					return (object) array( 'new_version' => '1.2.3+build.7' );
				},
			)
		);

		$this->intercept( $guard );

		$requests = $GLOBALS['__wp_http_requests'];
		$this->assertCount( 2, $requests, 'Offered-version fetch, then current-version fetch.' );

		$url = $requests[0]['url'];
		$this->assertStringContainsString( 'https://store.example?', $url );
		$this->assertStringContainsString( 'edd_action=get_release_signature', $url );
		$this->assertStringContainsString( 'slug=weird%2Bslug', $url, 'Slug must be rawurlencoded (add_query_arg does not encode).' );
		$this->assertStringContainsString( 'version=1.2.3%2Bbuild.7', $url, 'A "+" build suffix must survive as %2B.' );
		$this->assertStringContainsString( 'item_id=42', $url );

		$this->assertSame( 15, $requests[0]['args']['timeout'] );
		$this->assertSame( 8192, $requests[0]['args']['limit_response_size'], 'Response size must be capped at signature scale.' );

		// The race-healer fetch asks for the current version via version=''.
		$this->assertStringContainsString( 'version=&', $requests[1]['url'] . '&' );

		// Without item_id configured, the parameter is omitted entirely.
		wp_shims_reset();
		$guard = $this->makeGuard( array( 'signature_fetcher' => null ) );
		$this->intercept( $guard );

		$this->assertStringNotContainsString( 'item_id', $GLOBALS['__wp_http_requests'][0]['url'] );
	}

	public function testDefaultSignatureFetcherReturnsBodyOn200(): void {
		$GLOBALS['__wp_http_queue'][] = array(
			'response' => array( 'code' => 200 ),
			'body'     => file_get_contents( $this->fixture( 'sample-plugin-1.2.3.zip.minisig' ) ),
		);

		$guard  = $this->makeGuard( array( 'signature_fetcher' => null ) );
		$result = $this->intercept( $guard );

		$this->assertIsString( $result, 'The fetched body must flow into verification and pass.' );
		$this->assertCount( 1, $GLOBALS['__wp_http_requests'] );
	}

	public function fetcherFailureResponseProvider(): array {
		return array(
			'wp_error response' => array( null ),
			'non-200 status'    => array( array( 'response' => array( 'code' => 404 ), 'body' => 'Not Found' ) ),
			'empty body'        => array( array( 'response' => array( 'code' => 200 ), 'body' => '' ) ),
		);
	}

	/**
	 * defaultSignatureFetcher() must yield null (no candidate) on transport
	 * errors, non-200 statuses, and empty bodies — surfacing as a
	 * missing-signature failure rather than feeding junk to the parser.
	 *
	 * @dataProvider fetcherFailureResponseProvider
	 *
	 * @param array|null $response null leaves the queue empty (shim returns WP_Error).
	 */
	public function testDefaultSignatureFetcherReturnsNullOnFailureResponses( ?array $response ): void {
		if ( null !== $response ) {
			$GLOBALS['__wp_http_queue'][] = $response;
			$GLOBALS['__wp_http_queue'][] = $response; // Offered fetch + current fetch.
		}

		$guard  = $this->makeGuard( array( 'signature_fetcher' => null ) );
		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );

		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertSame( 'missing_signature', $failures['sample-plugin']['code'] );
	}

	public function testFailureActionReceivesContractArgsWhenBlocking(): void {
		$guard = $this->makeGuard( array( 'downloader' => $this->downloaderFor( 'sample-plugin-1.2.3.tampered.zip' ) ) );
		$this->intercept( $guard );

		$args = $this->firedActionArgs( 'pattonwebz_signed_releases_failure' );

		$this->assertNotNull( $args );
		$this->assertSame( 'sample-plugin', $args[0] );
		$this->assertInstanceOf( VerificationException::class, $args[1] );
		$this->assertSame( 'bad_signature', $args[1]->errorCode() );
		$this->assertSame( self::PACKAGE_URL, $args[2] );
		$this->assertTrue( $args[3], 'Enforce mode reports $blocked = true.' );
	}

	public function testFailureActionReportsNotBlockedInLogMode(): void {
		$guard = $this->makeGuard(
			array(
				'mode'       => VerificationPolicy::MODE_LOG,
				'downloader' => $this->downloaderFor( 'sample-plugin-1.2.3.tampered.zip' ),
			)
		);
		$this->intercept( $guard );

		$args = $this->firedActionArgs( 'pattonwebz_signed_releases_failure' );

		$this->assertNotNull( $args );
		$this->assertFalse( $args[3], 'Log mode reports $blocked = false.' );
	}

	public function testVerifiedActionReceivesContractArgs(): void {
		$result = $this->intercept( $this->makeGuard() );

		$args = $this->firedActionArgs( 'pattonwebz_signed_releases_verified' );

		$this->assertNotNull( $args );
		$this->assertSame( 'sample-plugin', $args[0] );
		$this->assertInstanceOf( TrustedComment::class, $args[1] );
		$this->assertSame( '1.2.3', $args[1]->get( 'version' ) );
		$this->assertSame( $result, $args[2], 'Action receives the same verified file path returned to WP.' );
	}

	public function testModeFilterCanEscalateLogToEnforce(): void {
		// The runtime filter works in both directions: a site can harden a
		// log-configured guard to enforce without a code change.
		$GLOBALS['__wp_filter_overrides']['pattonwebz_signed_releases_mode'] = VerificationPolicy::MODE_ENFORCE;

		$guard = $this->makeGuard(
			array(
				'mode'       => VerificationPolicy::MODE_LOG,
				'downloader' => $this->downloaderFor( 'sample-plugin-1.2.3.tampered.zip' ),
			)
		);

		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result, 'Escalated mode must block, not merely log.' );
	}

	public function corruptSeenOptionProvider(): array {
		return array(
			'string option' => array( 'corrupt-string' ),
			'int option'    => array( 42 ),
		);
	}

	/**
	 * The READ path (highWaterVersion) is isset()-safe against a corrupted
	 * OPTION_SEEN: a scalar option must simply mean "no high-water mark",
	 * leaving the installed-version floor to do its job.
	 *
	 * This deliberately drives a FAILURE (downgrade) path so no write happens;
	 * the write paths' scalar handling is covered separately by
	 * testCorruptSeenOptionIsReplacedOnRatchetWrite.
	 *
	 * @dataProvider corruptSeenOptionProvider
	 *
	 * @param mixed $corrupt
	 */
	public function testCorruptSeenOptionReadPathIsSafe( $corrupt ): void {
		update_option( UpdaterGuard::OPTION_SEEN, $corrupt );

		$guard  = $this->makeGuard( array( 'current_version' => '3.0.0' ) );
		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );

		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertSame( 'downgrade', $failures['sample-plugin']['code'], 'Installed-version floor still applies with a corrupt ratchet option.' );
		$this->assertSame( $corrupt, get_option( UpdaterGuard::OPTION_SEEN ), 'No write happens on a blocked install.' );
	}

	/**
	 * A scalar in OPTION_SEEN must not corrupt the option or drop the
	 * ratchet write: recordSeenVersion() starts over from a fresh array.
	 *
	 * @dataProvider corruptSeenOptionProvider
	 *
	 * @param mixed $corrupt
	 */
	public function testCorruptSeenOptionIsReplacedOnRatchetWrite( $corrupt ): void {
		update_option( UpdaterGuard::OPTION_SEEN, $corrupt );

		$guard  = $this->makeGuard();
		$result = $this->intercept( $guard );

		$this->assertIsString( $result, 'Verification itself must still succeed.' );
		$this->assertSame(
			array( 'sample-plugin' => '1.2.3' ),
			get_option( UpdaterGuard::OPTION_SEEN ),
			'The scalar is discarded and the ratchet records the verified version.'
		);
	}

	/**
	 * Same guarantee for the failure log: a scalar in OPTION_FAILURES is
	 * discarded by recordFailure() rather than corrupted in place.
	 *
	 * @dataProvider corruptSeenOptionProvider
	 *
	 * @param mixed $corrupt
	 */
	public function testCorruptFailuresOptionIsReplacedOnRecord( $corrupt ): void {
		update_option( UpdaterGuard::OPTION_FAILURES, $corrupt );

		$guard = $this->makeGuard(
			array(
				'mode'       => VerificationPolicy::MODE_LOG,
				'downloader' => $this->downloaderFor( 'sample-plugin-1.2.3.tampered.zip' ),
			)
		);

		$this->intercept( $guard );

		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertIsArray( $failures, 'The scalar is discarded, not written into.' );
		$this->assertSame( 'bad_signature', $failures['sample-plugin']['code'] );
	}

	public function testFirstCandidateFailureCodeIsTheOneRecorded(): void {
		// Candidate #1: the real signature with one bit flipped inside the
		// 64-byte file signature — parses fine, right key ID, fails the
		// crypto check (bad_signature). Candidates #2/#3: unparseable garbage
		// (malformed). The surfaced/recorded code must be the FIRST failure,
		// the most authoritative one.
		$lines  = preg_split( '/\R/', file_get_contents( $this->fixture( 'sample-plugin-1.2.3.zip.minisig' ) ) );
		$raw    = base64_decode( $lines[1], true );
		$raw[20] = chr( ord( $raw[20] ) ^ 0x01 ); // Inside the signature bytes, after alg(2) + key_id(8).
		$lines[1] = base64_encode( $raw );
		$flipped  = implode( "\n", $lines );

		$guard = $this->makeGuard(
			array(
				'update_resolver'   => static function () use ( $flipped ): object {
					return (object) array(
						'new_version' => '1.2.3',
						'signature'   => $flipped,
					);
				},
				'signature_fetcher' => static function (): ?string {
					return 'complete garbage, not a minisig';
				},
			)
		);

		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );

		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertSame( 'bad_signature', $failures['sample-plugin']['code'] );
	}

	public function nonStringTransientSignatureProvider(): array {
		return array(
			'array'        => array( array( 'unexpected' ) ),
			'int'          => array( 123 ),
			'empty string' => array( '' ),
		);
	}

	/**
	 * A wrong-typed `signature` on the transient row must be skipped as "no
	 * candidate", never fatal and never parsed.
	 *
	 * @dataProvider nonStringTransientSignatureProvider
	 *
	 * @param mixed $bad_signature
	 */
	public function testNonStringTransientSignatureIsSkipped( $bad_signature ): void {
		$guard = $this->makeGuard(
			array(
				'update_resolver'   => static function () use ( $bad_signature ): object {
					return (object) array(
						'new_version' => '1.2.3',
						'signature'   => $bad_signature,
					);
				},
				'signature_fetcher' => static function (): ?string {
					return null;
				},
			)
		);

		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );

		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertSame( 'missing_signature', $failures['sample-plugin']['code'] );
	}

	public function testNullUpdateResolverFallsBackToSingleCurrentFetch(): void {
		// No update row at all: no transient candidate, no offered-version
		// fetch — just one current-version ('') fetch, which can still verify.
		$fetches = array();

		$guard = $this->makeGuard(
			array(
				'update_resolver'   => static function (): ?object {
					return null;
				},
				'signature_fetcher' => function ( string $version ) use ( &$fetches ): ?string {
					$fetches[] = $version;

					return file_get_contents( $this->fixture( 'sample-plugin-1.2.3.zip.minisig' ) );
				},
			)
		);

		$this->assertIsString( $this->intercept( $guard ) );
		$this->assertSame( array( '' ), $fetches );
		$this->assertSame( '1.2.3', get_option( UpdaterGuard::OPTION_SEEN )['sample-plugin'] );
	}

	public function testKeyRotationVerifiesAgainstSecondTrustedKey(): void {
		// Rotation window: both keys configured; a release signed by the
		// second key (wrong-key.minisig is otherkey's genuine signature over
		// these bytes) must verify end-to-end through the guard.
		$guard = $this->makeGuard(
			array(
				'public_keys'       => array(
					file_get_contents( $this->fixture( 'testkey.pub' ) ),
					file_get_contents( $this->fixture( 'otherkey.pub' ) ),
				),
				'signature_fetcher' => function (): ?string {
					return file_get_contents( $this->fixture( 'wrong-key.minisig' ) );
				},
			)
		);

		$this->assertIsString( $this->intercept( $guard ) );
		$this->assertContains( 'pattonwebz_signed_releases_verified', $this->firedActions() );
	}

	public function requiredArgProvider(): array {
		return array(
			'plugin_file' => array( 'plugin_file' ),
			'slug'        => array( 'slug' ),
			'store_url'   => array( 'store_url' ),
			'public_keys' => array( 'public_keys' ),
		);
	}

	/**
	 * @dataProvider requiredArgProvider
	 */
	public function testConstructorRequiresCoreArgs( string $missing ): void {
		$args = $this->makeGuardArgs();
		unset( $args[ $missing ] );

		try {
			new UpdaterGuard( $args );
			$this->fail( 'Expected InvalidArgumentException.' );
		} catch ( \InvalidArgumentException $e ) {
			$this->assertStringContainsString( "'{$missing}'", $e->getMessage() );
		}
	}

	public function testConstructorRejectsEmptyPublicKeysArray(): void {
		try {
			new UpdaterGuard( $this->makeGuardArgs( array( 'public_keys' => array() ) ) );
			$this->fail( 'Expected InvalidArgumentException.' );
		} catch ( \InvalidArgumentException $e ) {
			$this->assertStringContainsString( "'public_keys'", $e->getMessage() );
		}
	}

	public function testAcceptsBarePublicKeyStringWithoutArrayWrapper(): void {
		// public_keys as a plain base64 string (no array, no newline) is
		// cast to a one-key array and parsed via fromBase64().
		$lines = array_values(
			array_filter( array_map( 'trim', file( $this->fixture( 'testkey.pub' ) ) ) )
		);

		$guard = $this->makeGuard( array( 'public_keys' => $lines[1] ) );

		$this->assertIsString( $this->intercept( $guard ) );
	}

	public function testSingleUntrustedCommentLineKeyFailsClosedViaRegister(): void {
		// A key text that is ONLY an 'untrusted comment:' line routes through
		// fromFileText() (no key material) — register() must fail closed:
		// null guard, this plugin's updates blocked.
		$guard = UpdaterGuard::register(
			$this->makeGuardArgs( array( 'public_keys' => array( 'untrusted comment: minisign public key 0123456789ABCDEF' ) ) )
		);

		$this->assertNull( $guard );

		$blocker = $this->lastCallbackFor( 'upgrader_pre_download' );
		$this->assertNotNull( $blocker );

		$result = $blocker( false, self::PACKAGE_URL, null, array( 'plugin' => self::PLUGIN_FILE ) );
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( 'pattonwebz_signed_releases_misconfigured', $result->get_error_code() );
	}

	public function testEmptyCurrentVersionIsToleratedOutsideEnforce(): void {
		// current_version '' is normalised to null (no installed-version
		// floor). In log mode that is allowed — nothing is blocked anyway —
		// so the guard constructs and verification proceeds.
		$guard = $this->makeGuard(
			array(
				'mode'            => VerificationPolicy::MODE_LOG,
				'current_version' => '',
			)
		);

		$this->assertIsString( $this->intercept( $guard ) );
	}

	public function testEnforceWithoutCurrentVersionFailsClosedAtConstruction(): void {
		// The enforce guarantee reduces to the downgrade floor, whose one
		// un-resettable input is the installed version. Configuring enforce
		// without it is a hard misconfiguration: register() must fail closed
		// (block this plugin's updates), never enforce with no floor.
		foreach ( array( '', null ) as $missing ) {
			$args = $this->makeGuardArgs( array( 'current_version' => $missing ) );
			if ( null === $missing ) {
				unset( $args['current_version'] );
			}

			$guard = UpdaterGuard::register( $args );
			$this->assertNull( $guard, 'Enforce without current_version must not construct.' );

			$blocker = $this->lastCallbackFor( 'upgrader_pre_download' );
			$this->assertNotNull( $blocker );

			$result = $blocker( false, self::PACKAGE_URL, null, array( 'plugin' => self::PLUGIN_FILE ) );
			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'pattonwebz_signed_releases_misconfigured', $result->get_error_code() );
			$this->assertStringContainsString( 'current_version', $result->get_error_message() );
		}
	}

	public function testRuntimeEscalationWithoutFloorFailsClosed(): void {
		// A guard constructed in log mode (no floor required) that the
		// kill-switch filter raises to enforce at runtime never passed the
		// constructor's floor check — interceptDownload must fail closed
		// rather than enforce with no downgrade floor.
		$GLOBALS['__wp_filter_overrides']['pattonwebz_signed_releases_mode'] = VerificationPolicy::MODE_ENFORCE;

		$guard = $this->makeGuard(
			array(
				'mode'            => VerificationPolicy::MODE_LOG,
				'current_version' => '',
				'downloader'      => static function (): string {
					throw new \LogicException( 'Must block before downloading.' );
				},
			)
		);

		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( 'pattonwebz_signed_releases_no_floor', $result->get_error_code() );
		$this->assertNotSame( array(), $this->logged );
	}

	public function testInvalidModeViaRegisterFailsClosed(): void {
		$guard = UpdaterGuard::register( $this->makeGuardArgs( array( 'mode' => 'banana' ) ) );

		$this->assertNull( $guard, 'An invalid mode must not throw out of register().' );

		$blocker = $this->lastCallbackFor( 'upgrader_pre_download' );
		$this->assertNotNull( $blocker );

		$result = $blocker( false, self::PACKAGE_URL, null, array( 'plugin' => self::PLUGIN_FILE ) );
		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertSame( 'pattonwebz_signed_releases_misconfigured', $result->get_error_code() );
		$this->assertStringContainsString( 'Unknown verification mode', $result->get_error_message() );
	}

	public function testNonArrayHookExtraPassesReplyThrough(): void {
		$guard = $this->makeGuard(
			array(
				'downloader' => static function (): string {
					throw new \LogicException( 'Downloader must not run without plugin context.' );
				},
			)
		);

		$this->assertFalse( $guard->interceptDownload( false, self::PACKAGE_URL, null, null ) );
		$this->assertFalse( $guard->interceptDownload( false, self::PACKAGE_URL, null, 'not-an-array' ) );
		$this->assertSame( 'earlier-reply', $guard->interceptDownload( 'earlier-reply', self::PACKAGE_URL, null, null ) );
	}

	public function testOffModeIsCompletelyInert(): void {
		// Off mode must not download, log, record options, or fire actions.
		$guard = $this->makeGuard(
			array(
				'mode'       => VerificationPolicy::MODE_OFF,
				'downloader' => static function (): string {
					throw new \LogicException( 'Downloader must not run in off mode.' );
				},
			)
		);

		$this->assertFalse( $this->intercept( $guard ) );
		$this->assertFalse( get_option( UpdaterGuard::OPTION_FAILURES ) );
		$this->assertFalse( get_option( UpdaterGuard::OPTION_SEEN ) );
		$this->assertSame( array(), $this->logged );
		$this->assertSame( array(), $this->firedActions() );
	}

	public function emptyResolverTransientProvider(): array {
		return array(
			'no transient at all'      => array( null ),
			'transient without response' => array( (object) array( 'checked' => array() ) ),
			'row is array not object'  => array(
				(object) array( 'response' => array( self::PLUGIN_FILE => array( 'new_version' => '1.2.3' ) ) ),
			),
		);
	}

	/**
	 * defaultUpdateResolver() (update_resolver => null) must yield null for
	 * every non-usable transient shape — observable as a single current
	 * ('') signature fetch with no offered-version fetch.
	 *
	 * @dataProvider emptyResolverTransientProvider
	 *
	 * @param object|null $transient
	 */
	public function testDefaultUpdateResolverYieldsNullForUnusableTransients( ?object $transient ): void {
		if ( null !== $transient ) {
			$GLOBALS['__wp_site_transients']['update_plugins'] = $transient;
		}

		$fetches = array();

		$guard = $this->makeGuard(
			array(
				'update_resolver'   => null,
				'signature_fetcher' => function ( string $version ) use ( &$fetches ): ?string {
					$fetches[] = $version;

					return file_get_contents( $this->fixture( 'sample-plugin-1.2.3.zip.minisig' ) );
				},
			)
		);

		$this->assertIsString( $this->intercept( $guard ) );
		$this->assertSame( array( '' ), $fetches, 'No usable row means no offered-version fetch.' );
	}

	public function testDefaultUpdateResolverReturnsThePluginRow(): void {
		$GLOBALS['__wp_site_transients']['update_plugins'] = (object) array(
			'response' => array(
				self::PLUGIN_FILE => (object) array( 'new_version' => '1.2.3' ),
				'other/other.php' => (object) array( 'new_version' => '9.9.9' ),
			),
		);

		$fetches = array();

		$guard = $this->makeGuard(
			array(
				'update_resolver'   => null,
				'signature_fetcher' => function ( string $version ) use ( &$fetches ): ?string {
					$fetches[] = $version;

					return file_get_contents( $this->fixture( 'sample-plugin-1.2.3.zip.minisig' ) );
				},
			)
		);

		$this->assertIsString( $this->intercept( $guard ) );
		$this->assertSame( array( '1.2.3' ), $fetches, 'Own row resolved: offered version is fetched (and verifies).' );
	}

	public function testEmptyVersionTokenInSignatureIsMissingVersion(): void {
		// 'version:' with no value parses to '' (not null) — the guard must
		// treat it exactly like an absent version: unbindable, blocked.
		$keypair = $this->makeSignerKeypair();
		$data    = 'in-test package bytes';
		$minisig = $this->signMinisig( $keypair, $data, 'slug:sample-plugin version: signed:2026-07-15T00:00:00Z' );

		$guard = $this->makeGuard(
			array(
				'public_keys'       => array( $keypair['public_b64'] ),
				'downloader'        => $this->downloaderForData( $data ),
				'signature_fetcher' => static function () use ( $minisig ): ?string {
					return $minisig;
				},
			)
		);

		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );

		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertSame( 'missing_version', $failures['sample-plugin']['code'] );
	}

	public function testPrereleaseOfferAcceptsNewerStableSigned(): void {
		// Offered 1.2.3-rc1, signed 1.2.3: version_compare ranks the stable
		// release newer, so this is the accept direction of the race rule.
		$guard = $this->makeGuard(
			array(
				'update_resolver' => static function (): object {
					return (object) array( 'new_version' => '1.2.3-rc1' );
				},
			)
		);

		$this->assertIsString( $this->intercept( $guard ) );
		$this->assertSame( '1.2.3', get_option( UpdaterGuard::OPTION_SEEN )['sample-plugin'] );
		$this->assertStringContainsString( 'replaced in place', $this->logged[0][1] );
	}

	public function testPrereleaseOfferBlocksOlderSigned(): void {
		// Offered 1.2.4-rc1, signed 1.2.3: the signed version is OLDER than
		// the offer — the replay direction — and must block.
		$guard = $this->makeGuard(
			array(
				'update_resolver' => static function (): object {
					return (object) array( 'new_version' => '1.2.4-rc1' );
				},
			)
		);

		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );

		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertSame( 'comment_mismatch', $failures['sample-plugin']['code'] );
	}

	public function testDuplicateSlugTokenFirstOccurrenceWinsEndToEnd(): void {
		// TrustedComment pins first-occurrence-wins; prove it holds through
		// the guard in both orders, so a trailing duplicate can neither
		// bypass nor cause a false rejection.
		$keypair = $this->makeSignerKeypair();
		$data    = 'in-test package bytes';

		$ours_first = $this->signMinisig( $keypair, $data, 'slug:sample-plugin slug:evil-plugin version:1.2.3' );
		$evil_first = $this->signMinisig( $keypair, $data, 'slug:evil-plugin slug:sample-plugin version:1.2.3' );

		$overrides = array(
			'public_keys' => array( $keypair['public_b64'] ),
			'downloader'  => $this->downloaderForData( $data ),
		);

		$guard = $this->makeGuard(
			array_merge(
				$overrides,
				array(
					'signature_fetcher' => static function () use ( $ours_first ): ?string {
						return $ours_first;
					},
				)
			)
		);
		$this->assertIsString( $this->intercept( $guard ), 'First token is our slug: verifies.' );

		$guard = $this->makeGuard(
			array_merge(
				$overrides,
				array(
					'signature_fetcher' => static function () use ( $evil_first ): ?string {
						return $evil_first;
					},
				)
			)
		);
		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result, 'First token is another slug: blocked.' );

		$failures = get_option( UpdaterGuard::OPTION_FAILURES );
		$this->assertSame( 'comment_mismatch', $failures['sample-plugin']['code'] );
	}
}
