<?php

declare(strict_types=1);

namespace PattonWebz\SignedReleases\Tests;

use PattonWebz\SignedReleases\RevocationList;
use PattonWebz\SignedReleases\UpdaterGuard;
use PattonWebz\SignedReleases\VerificationException;
use PattonWebz\SignedReleases\VerificationPolicy;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end revocation behaviour through interceptDownload(): the manifest
 * fetch/verify/merge flow, the per-pass revocation posture, and the
 * stolen-key emergency (revoke the active key, recover via the pre-staged
 * standing successor already pinned in public_keys).
 */
final class UpdaterGuardRevocationTest extends TestCase {

	use InTestSigner;

	private const PLUGIN_FILE = 'sample-plugin/sample-plugin.php';
	private const PACKAGE     = 'in-test package bytes';

	/** @var string[] */
	private array $tempFiles = array();

	/** @var array<int, array{0: string, 1: string}> */
	private array $logged = array();

	private int $manifestFetches = 0;

	/** @var array{secret: string, public_b64: string, key_id: string} */
	private array $activeKey;

	/** @var array{secret: string, public_b64: string, key_id: string} */
	private array $successorKey;

	/** @var array{secret: string, public_b64: string, key_id: string} */
	private array $rootKey;

	protected function setUp(): void {
		wp_shims_reset();
		$this->logged          = array();
		$this->manifestFetches = 0;
		$this->activeKey       = $this->makeSignerKeypair();
		$this->successorKey    = $this->makeSignerKeypair();
		$this->rootKey         = $this->makeSignerKeypair();
	}

	protected function tearDown(): void {
		foreach ( $this->tempFiles as $file ) {
			if ( file_exists( $file ) ) {
				unlink( $file );
			}
		}
		$this->tempFiles = array();
	}

	private function keyIdHex( array $keypair ): string {
		return strtoupper( bin2hex( strrev( $keypair['key_id'] ) ) );
	}

	private function packageMinisig( array $keypair, string $version = '1.2.3' ): string {
		return $this->signMinisig( $keypair, self::PACKAGE, sprintf( 'slug:sample-plugin version:%s signed:2026-07-18T00:00:00Z', $version ) );
	}

	/**
	 * A RevocationList scoped exactly as the guard scopes it — to the pinned
	 * root's full public key — so assertions read the same bucket the guard
	 * wrote (the option is per-root scoped, not global).
	 */
	private function revocationList(): RevocationList {
		$raw = substr( (string) base64_decode( $this->rootKey['public_b64'], true ), 10, 32 );

		return new RevocationList( strtoupper( bin2hex( $raw ) ) );
	}

	private function manifestJson( int $sequence, array $revoked, array $unrevoked = array() ): string {
		$entry = static function ( string $key_id ): array {
			return array(
				'key_id' => $key_id,
				'reason' => 'ci_secret_compromise',
			);
		};

		return json_encode(
			array(
				'format'         => 'pattonwebz-revocation-v1',
				'sequence'       => $sequence,
				'issued_at'      => '2026-07-18T14:00:00Z',
				'revoked_keys'   => array_map( $entry, $revoked ),
				'unrevoked_keys' => array_map( $entry, $unrevoked ),
			)
		);
	}

	/**
	 * The envelope body the store endpoint serves: manifest JSON plus its
	 * root signature, with the trusted comment mirroring the sequence.
	 */
	private function envelope( string $manifest_json, ?array $signing_key = null, ?string $trusted_comment = null ): string {
		$signing_key = $signing_key ?? $this->rootKey;
		$sequence    = json_decode( $manifest_json, true )['sequence'] ?? 0;
		$comment     = $trusted_comment ?? sprintf( 'revocation-manifest sequence:%d format:pattonwebz-revocation-v1', $sequence );

		return json_encode(
			array(
				'format'   => 'pattonwebz-revocation-envelope-v1',
				'manifest' => $manifest_json,
				'minisig'  => $this->signMinisig( $signing_key, $manifest_json, $comment ),
			)
		);
	}

	/** A fetcher serving fixed envelope bodies, counting calls. */
	private function fetcherFor( ?string ...$bodies ): callable {
		return function () use ( $bodies ): ?string {
			$body = $bodies[ min( $this->manifestFetches, count( $bodies ) - 1 ) ];
			++$this->manifestFetches;

			return $body;
		};
	}

	private function makeGuard( array $overrides = array() ): UpdaterGuard {
		$defaults = array(
			'plugin_file'         => self::PLUGIN_FILE,
			'slug'                => 'sample-plugin',
			'store_url'           => 'https://store.example',
			'public_keys'         => array( $this->activeKey['public_b64'], $this->successorKey['public_b64'] ),
			'mode'                => VerificationPolicy::MODE_ENFORCE,
			'current_version'     => '0.0.1',
			'revocation_root_key' => $this->rootKey['public_b64'],
			'revocation_mode'     => VerificationPolicy::MODE_ENFORCE,
			'downloader'          => function (): string {
				$tmp = tempnam( sys_get_temp_dir(), 'rev-test-' );
				file_put_contents( $tmp, self::PACKAGE );
				$this->tempFiles[] = $tmp;

				return $tmp;
			},
			'signature_fetcher'   => function (): ?string {
				return $this->packageMinisig( $this->activeKey );
			},
			'revocation_fetcher'  => $this->fetcherFor( null ),
			'update_resolver'     => static function (): object {
				return (object) array( 'new_version' => '1.2.3' );
			},
			'logger'              => function ( string $level, string $message ): void {
				$this->logged[] = array( $level, $message );
			},
		);

		return new UpdaterGuard( array_merge( $defaults, $overrides ) );
	}

	private function intercept( UpdaterGuard $guard ) {
		return $guard->interceptDownload( false, 'https://store.example/package', null, array( 'plugin' => self::PLUGIN_FILE ) );
	}

	private function loggedMessages(): string {
		return implode( "\n", array_column( $this->logged, 1 ) );
	}

	public function testStolenKeyEmergencyEndToEnd(): void {
		// The design memo's §4 walkthrough: the active key is revoked by a
		// root-signed manifest, the emergency release is signed with the
		// pre-staged successor, and the update succeeds with no key change
		// ever shipped to the client.
		$manifest = $this->envelope( $this->manifestJson( 1, array( $this->keyIdHex( $this->activeKey ) ) ) );

		// The attacker's push: still signed with the stolen active key.
		$guard = $this->makeGuard( array( 'revocation_fetcher' => $this->fetcherFor( $manifest ) ) );

		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result );
		$this->assertStringContainsString( 'revoked', $result->get_error_message() );

		// The emergency release: same guard config, successor-signed package.
		$guard = $this->makeGuard(
			array(
				'revocation_fetcher' => $this->fetcherFor( $manifest ),
				'signature_fetcher'  => function (): ?string {
					return $this->packageMinisig( $this->successorKey );
				},
			)
		);

		$result = $this->intercept( $guard );

		$this->assertIsString( $result );
		$this->assertFileExists( $result );
	}

	public function testRevocationFailureReportsRevokedKeyCode(): void {
		$manifest = $this->envelope( $this->manifestJson( 1, array( $this->keyIdHex( $this->activeKey ) ) ) );
		$guard    = $this->makeGuard(
			array(
				'public_keys'        => array( $this->activeKey['public_b64'] ),
				'revocation_fetcher' => $this->fetcherFor( $manifest ),
			)
		);

		$this->assertInstanceOf( \WP_Error::class, $this->intercept( $guard ) );

		foreach ( $GLOBALS['__wp_actions'] as $action ) {
			if ( 'pattonwebz_signed_releases_failure' === $action['tag'] ) {
				$this->assertSame( VerificationException::REVOKED_KEY, $action['args'][1]->errorCode() );

				return;
			}
		}

		$this->fail( 'Failure action never fired.' );
	}

	public function testLogModeRevocationAllowsAndWarns(): void {
		$manifest = $this->envelope( $this->manifestJson( 1, array( $this->keyIdHex( $this->activeKey ) ) ) );
		$guard    = $this->makeGuard(
			array(
				'revocation_mode'    => VerificationPolicy::MODE_LOG,
				'revocation_fetcher' => $this->fetcherFor( $manifest ),
			)
		);

		$result = $this->intercept( $guard );

		$this->assertIsString( $result );
		$this->assertStringContainsString( 'log mode', $this->loggedMessages() );
		$this->assertStringContainsString( $this->keyIdHex( $this->activeKey ), $this->loggedMessages() );
	}

	public function testFetchFailureIsSilentSafe(): void {
		$guard = $this->makeGuard( array( 'revocation_fetcher' => $this->fetcherFor( null ) ) );

		$result = $this->intercept( $guard );

		$this->assertIsString( $result );
		$this->assertStringContainsString( 'keeping the cached list', $this->loggedMessages() );
	}

	public function testGarbageEnvelopeIsRejectedQuietly(): void {
		$guard = $this->makeGuard( array( 'revocation_fetcher' => $this->fetcherFor( '{"nope":true}' ) ) );

		$this->assertIsString( $this->intercept( $guard ) );
		$this->assertStringContainsString( 'not a recognised envelope', $this->loggedMessages() );
	}

	public function testManifestSignedByAPackageKeyIsRejected(): void {
		// Only the root signs manifests. A manifest signed by the (possibly
		// stolen) active package key must not revoke anything — otherwise a
		// stolen package key could sabotage the fleet's trust set.
		$manifest = $this->envelope(
			$this->manifestJson( 1, array( $this->keyIdHex( $this->successorKey ) ) ),
			$this->activeKey
		);

		$guard = $this->makeGuard(
			array(
				'revocation_fetcher' => $this->fetcherFor( $manifest ),
				'signature_fetcher'  => function (): ?string {
					return $this->packageMinisig( $this->successorKey );
				},
			)
		);

		$result = $this->intercept( $guard );

		$this->assertIsString( $result, 'Successor must still verify: the bogus manifest revoked nothing.' );
		$this->assertStringContainsString( 'rejected', $this->loggedMessages() );
		$this->assertFalse( $this->revocationList()->isRevoked( $this->keyIdHex( $this->successorKey ) ) );
	}

	public function testRollbackManifestIsIgnored(): void {
		$revoke_active = $this->envelope( $this->manifestJson( 3, array( $this->keyIdHex( $this->activeKey ) ) ) );
		$stale_replay  = $this->envelope( $this->manifestJson( 2, array(), array( $this->keyIdHex( $this->activeKey ) ) ) );

		$this->assertInstanceOf(
			\WP_Error::class,
			$this->intercept( $this->makeGuard( array( 'revocation_fetcher' => $this->fetcherFor( $revoke_active ) ) ) )
		);

		// A hostile/MITM store replays validly-signed history to un-revoke.
		$this->logged = array();
		$result       = $this->intercept( $this->makeGuard( array( 'revocation_fetcher' => $this->fetcherFor( $stale_replay ) ) ) );

		$this->assertInstanceOf( \WP_Error::class, $result, 'The ratchet must keep the revocation.' );
		$this->assertStringContainsString( 'revocation_manifest_rollback', $this->loggedMessages() );
	}

	public function testExplicitUnrevokeRestoresTheKey(): void {
		$revoke   = $this->envelope( $this->manifestJson( 1, array( $this->keyIdHex( $this->activeKey ) ) ) );
		$unrevoke = $this->envelope( $this->manifestJson( 2, array(), array( $this->keyIdHex( $this->activeKey ) ) ) );

		$this->assertInstanceOf(
			\WP_Error::class,
			$this->intercept( $this->makeGuard( array( 'revocation_fetcher' => $this->fetcherFor( $revoke ) ) ) )
		);

		$result = $this->intercept( $this->makeGuard( array( 'revocation_fetcher' => $this->fetcherFor( $unrevoke ) ) ) );

		$this->assertIsString( $result, 'An explicit, root-signed un-revoke restores the key.' );
	}

	public function testNoRootKeyMeansNoFetchAndNoCheck(): void {
		$guard = $this->makeGuard(
			array(
				'revocation_root_key' => null,
				'revocation_fetcher'  => $this->fetcherFor( null ),
			)
		);

		$this->assertIsString( $this->intercept( $guard ) );
		$this->assertSame( 0, $this->manifestFetches );
	}

	public function testRevocationModeOffMeansNoFetch(): void {
		$guard = $this->makeGuard(
			array(
				'revocation_mode'    => VerificationPolicy::MODE_OFF,
				'revocation_fetcher' => $this->fetcherFor( null ),
			)
		);

		$this->assertIsString( $this->intercept( $guard ) );
		$this->assertSame( 0, $this->manifestFetches );
	}

	public function testRevocationModeFilterCanRaiseToEnforce(): void {
		$manifest = $this->envelope( $this->manifestJson( 1, array( $this->keyIdHex( $this->activeKey ) ) ) );
		$guard    = $this->makeGuard(
			array(
				'revocation_mode'    => VerificationPolicy::MODE_LOG,
				'revocation_fetcher' => $this->fetcherFor( $manifest ),
			)
		);

		$GLOBALS['__wp_filter_overrides']['pattonwebz_signed_releases_revocation_mode'] = VerificationPolicy::MODE_ENFORCE;

		$this->assertInstanceOf( \WP_Error::class, $this->intercept( $guard ) );
	}

	public function testInvalidRevocationModeFilterFallsBackToConfigured(): void {
		$manifest = $this->envelope( $this->manifestJson( 1, array( $this->keyIdHex( $this->activeKey ) ) ) );
		$guard    = $this->makeGuard( array( 'revocation_fetcher' => $this->fetcherFor( $manifest ) ) );

		$GLOBALS['__wp_filter_overrides']['pattonwebz_signed_releases_revocation_mode'] = 'bogus';

		$this->assertInstanceOf( \WP_Error::class, $this->intercept( $guard ), 'Configured enforce mode must win over a bogus filter value.' );
		$this->assertStringContainsString( 'invalid mode', $this->loggedMessages() );
	}

	public function testMirrorMismatchWarnsButTrustsBody(): void {
		$json     = $this->manifestJson( 1, array( $this->keyIdHex( $this->activeKey ) ) );
		$manifest = $this->envelope( $json, null, 'revocation-manifest sequence:9 format:pattonwebz-revocation-v1' );

		$result = $this->intercept( $this->makeGuard( array( 'revocation_fetcher' => $this->fetcherFor( $manifest ) ) ) );

		$this->assertInstanceOf( \WP_Error::class, $result, 'The signed body still applies.' );
		$this->assertStringContainsString( 'disagrees with the signed body', $this->loggedMessages() );
		$this->assertSame( 1, $this->revocationList()->sequence(), 'The body sequence, not the mirror, is what ratchets.' );
	}

	public function testUnknownFutureManifestFormatFailsClosed(): void {
		$json = json_encode(
			array(
				'format'       => 'pattonwebz-revocation-v2',
				'sequence'     => 1,
				'revoked_keys' => array( array( 'key_id' => $this->keyIdHex( $this->activeKey ) ) ),
			)
		);

		$result = $this->intercept( $this->makeGuard( array( 'revocation_fetcher' => $this->fetcherFor( $this->envelope( $json ) ) ) ) );

		$this->assertIsString( $result, 'An unrecognised manifest shape must be ignored, not misread.' );
		$this->assertStringContainsString( 'rejected', $this->loggedMessages() );
		$this->assertFalse( $this->revocationList()->isRevoked( $this->keyIdHex( $this->activeKey ) ) );
	}

	public function testRevocationEnforceBlocksEvenWhenMainModeIsLog(): void {
		// The headline independence guarantee, and the shipped default combo:
		// package verification still soaking in log mode, revocation already
		// enforcing. A revoked key MUST block regardless of the main mode —
		// this is the exact case the mode-coupling bug let through.
		$manifest = $this->envelope( $this->manifestJson( 1, array( $this->keyIdHex( $this->activeKey ) ) ) );
		$guard    = $this->makeGuard(
			array(
				'mode'               => VerificationPolicy::MODE_LOG,
				'revocation_mode'    => VerificationPolicy::MODE_ENFORCE,
				'public_keys'        => array( $this->activeKey['public_b64'] ),
				'revocation_fetcher' => $this->fetcherFor( $manifest ),
			)
		);

		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result, 'revocation_mode=enforce must block a revoked key even while mode=log.' );
		$this->assertStringContainsString( 'blocked', $result->get_error_message() );
	}

	public function testRevocationEnforceBlocksEvenWhenMainModeIsOff(): void {
		// mode=off is the main-verification kill switch, but the two switches
		// are independent: revocation_mode=enforce must still fetch, check, and
		// block a revoked key. (Before the fix, isOff() short-circuited before
		// revocation ran at all.)
		$manifest = $this->envelope( $this->manifestJson( 1, array( $this->keyIdHex( $this->activeKey ) ) ) );
		$guard    = $this->makeGuard(
			array(
				'mode'               => VerificationPolicy::MODE_OFF,
				'revocation_mode'    => VerificationPolicy::MODE_ENFORCE,
				'public_keys'        => array( $this->activeKey['public_b64'] ),
				'revocation_fetcher' => $this->fetcherFor( $manifest ),
			)
		);

		$result = $this->intercept( $guard );

		$this->assertInstanceOf( \WP_Error::class, $result, 'revocation_mode=enforce must block even under mode=off.' );
		$this->assertSame( 1, $this->manifestFetches, 'Revocation must actually run (fetch) under mode=off.' );
	}

	public function testMainEnforceStillAllowsWhenRevocationIsOff(): void {
		// The other axis: a validly-signed, unrevoked package installs normally
		// with revocation switched off, and no manifest fetch happens.
		$guard = $this->makeGuard(
			array(
				'revocation_mode'    => VerificationPolicy::MODE_OFF,
				'revocation_fetcher' => $this->fetcherFor( $this->envelope( $this->manifestJson( 1, array( $this->keyIdHex( $this->activeKey ) ) ) ) ),
			)
		);

		$this->assertIsString( $this->intercept( $guard ) );
		$this->assertSame( 0, $this->manifestFetches );
	}

	public function testTamperedManifestBodyIsRejected(): void {
		// The signed bytes are altered after signing: the root signature no
		// longer matches, so the manifest is discarded (silent-safe) and the
		// key it named is NOT revoked.
		$valid   = $this->envelope( $this->manifestJson( 1, array( $this->keyIdHex( $this->activeKey ) ) ) );
		$decoded = json_decode( $valid, true );
		// Flip the sequence in the manifest body only; leave the .minisig as-is.
		$decoded['manifest'] = str_replace( '"sequence":1', '"sequence":2', $decoded['manifest'] );
		$tampered            = json_encode( $decoded );

		$guard = $this->makeGuard(
			array(
				'public_keys'        => array( $this->activeKey['public_b64'], $this->successorKey['public_b64'] ),
				'revocation_fetcher' => $this->fetcherFor( $tampered ),
				'signature_fetcher'  => function (): ?string {
					return $this->packageMinisig( $this->successorKey );
				},
			)
		);

		$result = $this->intercept( $guard );

		$this->assertIsString( $result, 'A tampered manifest must be discarded, not applied.' );
		$this->assertStringContainsString( 'rejected', $this->loggedMessages() );
		$this->assertFalse( $this->revocationList()->isRevoked( $this->keyIdHex( $this->activeKey ) ) );
	}

	public function testForgedTrustedCommentOnManifestIsRejected(): void {
		// Splice a different (validly self-consistent) minisig over the same
		// manifest body but signed by a NON-root key: global-signature /
		// root-key verification must reject it. Nothing is revoked.
		$manifest_json = $this->manifestJson( 1, array( $this->keyIdHex( $this->activeKey ) ) );
		$forged        = json_encode(
			array(
				'format'   => 'pattonwebz-revocation-envelope-v1',
				'manifest' => $manifest_json,
				// Signed by the active (package) key, not the root.
				'minisig'  => $this->signMinisig( $this->activeKey, $manifest_json, 'revocation-manifest sequence:1 format:pattonwebz-revocation-v1' ),
			)
		);

		$guard = $this->makeGuard(
			array(
				'public_keys'        => array( $this->activeKey['public_b64'], $this->successorKey['public_b64'] ),
				'revocation_fetcher' => $this->fetcherFor( $forged ),
				'signature_fetcher'  => function (): ?string {
					return $this->packageMinisig( $this->successorKey );
				},
			)
		);

		$this->assertIsString( $this->intercept( $guard ), 'A non-root-signed manifest must revoke nothing.' );
		$this->assertFalse( $this->revocationList()->isRevoked( $this->keyIdHex( $this->activeKey ) ) );
	}

	public function testRevocationIsSharedAcrossPluginsPinningTheSameRoot(): void {
		// The store-wide sharing the design intends: guard A (plugin-a) fetches
		// and applies a manifest; guard B (plugin-b, SAME root, its own fetcher
		// returning nothing) still sees the key revoked via the shared bucket.
		$manifest = $this->envelope( $this->manifestJson( 1, array( $this->keyIdHex( $this->activeKey ) ) ) );

		$guardA = $this->makeGuard(
			array(
				'plugin_file'        => 'plugin-a/plugin-a.php',
				'slug'               => 'plugin-a',
				'public_keys'        => array( $this->activeKey['public_b64'] ),
				'revocation_fetcher' => $this->fetcherFor( $manifest ),
			)
		);
		$guardA->interceptDownload( false, 'https://store.example/a', null, array( 'plugin' => 'plugin-a/plugin-a.php' ) );

		$this->assertTrue( $this->revocationList()->isRevoked( $this->keyIdHex( $this->activeKey ) ) );

		// Guard B: different plugin, same root, fetches nothing itself.
		$guardB = $this->makeGuard(
			array(
				'plugin_file'        => 'plugin-b/plugin-b.php',
				'slug'               => 'plugin-b',
				'public_keys'        => array( $this->activeKey['public_b64'] ),
				'signature_fetcher'  => function (): ?string {
					return $this->packageMinisig( $this->activeKey );
				},
				'revocation_fetcher' => $this->fetcherFor( null ),
			)
		);

		$result = $guardB->interceptDownload( false, 'https://store.example/b', null, array( 'plugin' => 'plugin-b/plugin-b.php' ) );

		$this->assertInstanceOf( \WP_Error::class, $result, 'A shared-root sibling plugin must honour the revocation.' );
	}

	public function testRevocationIsIsolatedAcrossDifferentRoots(): void {
		// The cross-vendor DoS fix at the guard level: guard A pins root A and
		// revokes a key ID; guard B pins a DIFFERENT root and legitimately
		// signs with that same key ID. Guard B's update must NOT be blocked.
		$otherRoot = $this->makeSignerKeypair();
		$victimKey = $this->activeKey; // guard B's real, never-compromised key.

		// Guard A (root A) revokes victimKey's ID.
		$manifestA = json_encode(
			array(
				'format'   => 'pattonwebz-revocation-envelope-v1',
				'manifest' => $this->manifestJson( 1, array( $this->keyIdHex( $victimKey ) ) ),
				'minisig'  => $this->signMinisig( $this->rootKey, $this->manifestJson( 1, array( $this->keyIdHex( $victimKey ) ) ), 'revocation-manifest sequence:1 format:pattonwebz-revocation-v1' ),
			)
		);
		$guardA = $this->makeGuard(
			array(
				'plugin_file'        => 'a/a.php',
				'slug'               => 'plugin-a',
				'revocation_fetcher' => $this->fetcherFor( $manifestA ),
			)
		);
		$guardA->interceptDownload( false, 'https://a/a', null, array( 'plugin' => 'a/a.php' ) );

		// Guard B pins the OTHER root, signs its package with victimKey.
		$guardB = new UpdaterGuard(
			array(
				'plugin_file'         => 'b/b.php',
				'slug'                => 'plugin-b',
				'store_url'           => 'https://store.example',
				'public_keys'         => array( $victimKey['public_b64'] ),
				'mode'                => VerificationPolicy::MODE_ENFORCE,
				'revocation_mode'     => VerificationPolicy::MODE_ENFORCE,
				'current_version'     => '0.0.1',
				'revocation_root_key' => $otherRoot['public_b64'],
				'downloader'          => function (): string {
					$tmp = tempnam( sys_get_temp_dir(), 'rev-b-' );
					file_put_contents( $tmp, self::PACKAGE );
					$this->tempFiles[] = $tmp;

					return $tmp;
				},
				'signature_fetcher'   => function () use ( $victimKey ): ?string {
					return $this->signMinisig( $victimKey, self::PACKAGE, 'slug:plugin-b version:1.2.3' );
				},
				'revocation_fetcher'  => static function (): ?string {
					return null;
				},
				'update_resolver'     => static function (): object {
					return (object) array( 'new_version' => '1.2.3' );
				},
				'logger'              => function ( string $l, string $m ): void {
					$this->logged[] = array( $l, $m );
				},
			)
		);

		$result = $guardB->interceptDownload( false, 'https://store.example/b', null, array( 'plugin' => 'b/b.php' ) );

		$this->assertIsString( $result, "A different vendor's root must not be able to revoke guard B's key." );
	}
}
