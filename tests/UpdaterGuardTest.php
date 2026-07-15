<?php

declare(strict_types=1);

namespace PattonWebz\SignedReleases\Tests;

use PattonWebz\SignedReleases\UpdaterGuard;
use PattonWebz\SignedReleases\VerificationPolicy;
use PHPUnit\Framework\TestCase;

final class UpdaterGuardTest extends TestCase {

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

	private function makeGuard( array $overrides = array() ): UpdaterGuard {
		$defaults = array(
			'plugin_file'       => self::PLUGIN_FILE,
			'slug'              => 'sample-plugin',
			'store_url'         => 'https://store.example',
			'public_keys'       => array( file_get_contents( $this->fixture( 'testkey.pub' ) ) ),
			'mode'              => VerificationPolicy::MODE_ENFORCE,
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

		return new UpdaterGuard( array_merge( $defaults, $overrides ) );
	}

	private function intercept( UpdaterGuard $guard, array $hook_extra = array( 'plugin' => self::PLUGIN_FILE ) ) {
		return $guard->interceptDownload( false, self::PACKAGE_URL, null, $hook_extra );
	}

	private function firedActions(): array {
		return array_column( $GLOBALS['__wp_actions'], 'tag' );
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

	public function testPassesThroughExistingReply(): void {
		$guard = $this->makeGuard();

		$this->assertSame(
			'/already/handled.zip',
			$guard->interceptDownload( '/already/handled.zip', self::PACKAGE_URL, null, array( 'plugin' => self::PLUGIN_FILE ) )
		);
	}

	public function testOffModeDoesNothing(): void {
		$guard = $this->makeGuard( array( 'mode' => VerificationPolicy::MODE_OFF ) );

		$this->assertFalse( $this->intercept( $guard ) );
	}

	public function testModeFilterActsAsKillSwitch(): void {
		$GLOBALS['__wp_filter_overrides']['pattonwebz_signed_releases_mode'] = VerificationPolicy::MODE_OFF;

		$this->assertFalse( $this->intercept( $this->makeGuard() ) );
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
	}

	public function testAcceptsBareBase64PublicKey(): void {
		$lines = array_values(
			array_filter( array_map( 'trim', file( $this->fixture( 'testkey.pub' ) ) ) )
		);

		$guard = $this->makeGuard( array( 'public_keys' => array( $lines[1] ) ) );

		$this->assertIsString( $this->intercept( $guard ) );
	}
}
