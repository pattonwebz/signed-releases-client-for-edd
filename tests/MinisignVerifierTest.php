<?php

declare(strict_types=1);

namespace PattonWebz\SignedReleases\Tests;

use PattonWebz\SignedReleases\MinisignVerifier;
use PattonWebz\SignedReleases\PublicKey;
use PattonWebz\SignedReleases\Signature;
use PattonWebz\SignedReleases\VerificationException;
use PHPUnit\Framework\TestCase;

class MinisignVerifierTest extends TestCase {

	use InTestSigner;

	protected function fixture( string $name ): string {
		return PATTONWEBZ_TEST_FIXTURES . '/' . $name;
	}

	protected function key( string $name = 'testkey.pub' ): PublicKey {
		return PublicKey::fromFileText( file_get_contents( $this->fixture( $name ) ) );
	}

	protected function signature( string $name ): Signature {
		return Signature::fromMinisigText( file_get_contents( $this->fixture( $name ) ) );
	}

	/**
	 * Overridden by the sodium_compat suite to force the polyfill.
	 */
	protected function makeVerifier( array $keys ): MinisignVerifier {
		return new MinisignVerifier( $keys );
	}

	public function testValidZipVerifiesAndReturnsTrustedComment(): void {
		$verifier = $this->makeVerifier( array( $this->key() ) );

		$comment = $verifier->verifyFile(
			$this->fixture( 'sample-plugin-1.2.3.zip' ),
			$this->signature( 'sample-plugin-1.2.3.zip.minisig' )
		);

		$this->assertSame( 'sample-plugin', $comment->get( 'slug' ) );
		$this->assertSame( '1.2.3', $comment->get( 'version' ) );

		$comment->assertMatches( 'sample-plugin', '1.2.3' );
	}

	public function testTamperedZipFails(): void {
		$verifier = $this->makeVerifier( array( $this->key() ) );

		try {
			$verifier->verifyFile(
				$this->fixture( 'sample-plugin-1.2.3.tampered.zip' ),
				$this->signature( 'sample-plugin-1.2.3.zip.minisig' )
			);
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::BAD_SIGNATURE, $e->errorCode() );
		}
	}

	public function testSignatureFromUntrustedKeyIsRejected(): void {
		$verifier = $this->makeVerifier( array( $this->key() ) );

		try {
			$verifier->verifyFile(
				$this->fixture( 'sample-plugin-1.2.3.zip' ),
				$this->signature( 'wrong-key.minisig' )
			);
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::NO_MATCHING_KEY, $e->errorCode() );

			// The message names the unknown key in minisign's own hex display
			// form so an operator can match it against key inventory. This is
			// also the only caller of Signature::keyIdHex().
			$this->assertStringContainsString(
				$this->key( 'otherkey.pub' )->keyIdHex(),
				$e->getMessage()
			);
		}
	}

	public function testAlteredTrustedCommentFailsGlobalSignature(): void {
		$text = file_get_contents( $this->fixture( 'sample-plugin-1.2.3.zip.minisig' ) );
		// An attacker rewrites the trusted comment to claim a newer version.
		$text = str_replace( 'version:1.2.3', 'version:1.2.4', $text );

		$verifier = $this->makeVerifier( array( $this->key() ) );

		try {
			$verifier->verifyFile(
				$this->fixture( 'sample-plugin-1.2.3.zip' ),
				Signature::fromMinisigText( $text )
			);
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::BAD_GLOBAL_SIGNATURE, $e->errorCode() );
		}
	}

	public function testVersionMismatchInTrustedCommentIsCaughtByAssert(): void {
		$verifier = $this->makeVerifier( array( $this->key() ) );

		// Crypto is valid — the pipeline signed the wrong version string.
		$comment = $verifier->verifyFile(
			$this->fixture( 'sample-plugin-1.2.3.zip' ),
			$this->signature( 'version-mismatch.minisig' )
		);

		try {
			$comment->assertMatches( 'sample-plugin', '1.2.3' );
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::COMMENT_MISMATCH, $e->errorCode() );
		}
	}

	public function testSlugMismatchInTrustedCommentIsCaughtByAssert(): void {
		$verifier = $this->makeVerifier( array( $this->key() ) );

		$comment = $verifier->verifyFile(
			$this->fixture( 'sample-plugin-1.2.3.zip' ),
			$this->signature( 'slug-mismatch.minisig' )
		);

		try {
			$comment->assertMatches( 'sample-plugin', '1.2.3' );
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::COMMENT_MISMATCH, $e->errorCode() );
			$this->assertStringContainsString( 'evil-plugin', $e->getMessage() );
			$this->assertStringContainsString( 'sample-plugin', $e->getMessage() );
		}
	}

	public function testMultipleTrustedKeysSelectsByKeyId(): void {
		// Both keys trusted (rotation window): each signature verifies
		// against the key that actually made it.
		$verifier = $this->makeVerifier( array( $this->key( 'otherkey.pub' ), $this->key() ) );

		$comment = $verifier->verifyFile(
			$this->fixture( 'sample-plugin-1.2.3.zip' ),
			$this->signature( 'sample-plugin-1.2.3.zip.minisig' )
		);
		$this->assertSame( 'sample-plugin', $comment->get( 'slug' ) );

		$comment = $verifier->verifyFile(
			$this->fixture( 'sample-plugin-1.2.3.zip' ),
			$this->signature( 'wrong-key.minisig' )
		);
		$this->assertSame( 'sample-plugin', $comment->get( 'slug' ) );
	}

	public function testMissingFileThrowsUnreadable(): void {
		$verifier = $this->makeVerifier( array( $this->key() ) );

		try {
			$verifier->verifyFile(
				$this->fixture( 'does-not-exist.zip' ),
				$this->signature( 'sample-plugin-1.2.3.zip.minisig' )
			);
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::UNREADABLE, $e->errorCode() );
		}
	}

	public function testRequiresAtLeastOneKey(): void {
		$this->expectException( \InvalidArgumentException::class );
		$this->makeVerifier( array() );
	}

	public function testVerifyStringMatchesVerifyFileOnValidData(): void {
		$verifier = $this->makeVerifier( array( $this->key() ) );
		$sig      = $this->signature( 'sample-plugin-1.2.3.zip.minisig' );

		$comment = $verifier->verifyString(
			file_get_contents( $this->fixture( 'sample-plugin-1.2.3.zip' ) ),
			$sig
		);

		$this->assertSame( 'sample-plugin', $comment->get( 'slug' ) );
		$this->assertSame( '1.2.3', $comment->get( 'version' ) );

		// Same authenticated comment as the streaming file path.
		$file_comment = $verifier->verifyFile( $this->fixture( 'sample-plugin-1.2.3.zip' ), $sig );
		$this->assertSame( $file_comment->raw(), $comment->raw() );
	}

	public function testVerifyStringRejectsTamperedBytes(): void {
		$verifier = $this->makeVerifier( array( $this->key() ) );
		$data     = file_get_contents( $this->fixture( 'sample-plugin-1.2.3.zip' ) );
		$data[100] = chr( ord( $data[100] ) ^ 0xFF );

		try {
			$verifier->verifyString( $data, $this->signature( 'sample-plugin-1.2.3.zip.minisig' ) );
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::BAD_SIGNATURE, $e->errorCode() );
		}
	}

	public function testSplicedTrustedCommentAndGlobalSignatureRejected(): void {
		// Splice attack: keep the genuine untrusted comment + file signature
		// (lines 1-2 from the real testkey minisig, so the key ID matches and
		// the file check passes), but graft on another signature's trusted
		// comment + global signature (lines 3-4 from wrong-key.minisig). The
		// global signature cannot verify under the testkey — the trusted
		// comment is not authenticated and must be rejected.
		$good  = preg_split( '/\R/', file_get_contents( $this->fixture( 'sample-plugin-1.2.3.zip.minisig' ) ) );
		$other = preg_split( '/\R/', file_get_contents( $this->fixture( 'wrong-key.minisig' ) ) );

		$spliced = implode( "\n", array( $good[0], $good[1], $other[2], $other[3] ) );

		$verifier = $this->makeVerifier( array( $this->key() ) );

		try {
			$verifier->verifyFile(
				$this->fixture( 'sample-plugin-1.2.3.zip' ),
				Signature::fromMinisigText( $spliced )
			);
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::BAD_GLOBAL_SIGNATURE, $e->errorCode() );
		}
	}

	public function testEmptyFileVerifiesAndMatchesVerifyString(): void {
		// Zero-byte input is a valid message: the prehash of '' signs fine
		// and the empty-chunk guard in hashFileContents must not break it.
		$keypair = $this->makeSignerKeypair();
		$minisig = $this->signMinisig( $keypair, '', 'slug:empty-plugin version:0.0.1' );

		$verifier = $this->makeVerifier( array( PublicKey::fromBase64( $keypair['public_b64'] ) ) );
		$sig      = Signature::fromMinisigText( $minisig );

		$tmp = tempnam( sys_get_temp_dir(), 'sig-test-empty-' );

		try {
			$file_comment   = $verifier->verifyFile( $tmp, $sig );
			$string_comment = $verifier->verifyString( '', $sig );

			$this->assertSame( 'empty-plugin', $file_comment->get( 'slug' ) );
			$this->assertSame( $string_comment->raw(), $file_comment->raw() );
		} finally {
			unlink( $tmp );
		}
	}

	public function testMultiChunkFileVerifiesAndMatchesVerifyString(): void {
		// ~200 KB forces several 64 KiB fread/hashUpdate iterations, proving
		// the streamed prehash equals the one-shot prehash of the same bytes.
		$keypair = $this->makeSignerKeypair();
		$data    = str_repeat( "multi-chunk payload\n", 10000 ); // 200,000 bytes.
		$minisig = $this->signMinisig( $keypair, $data, 'slug:big-plugin version:2.0.0' );

		$verifier = $this->makeVerifier( array( PublicKey::fromBase64( $keypair['public_b64'] ) ) );
		$sig      = Signature::fromMinisigText( $minisig );

		$tmp = tempnam( sys_get_temp_dir(), 'sig-test-big-' );
		file_put_contents( $tmp, $data );

		try {
			$file_comment   = $verifier->verifyFile( $tmp, $sig );
			$string_comment = $verifier->verifyString( $data, $sig );

			$this->assertSame( 'big-plugin', $file_comment->get( 'slug' ) );
			$this->assertSame( $string_comment->raw(), $file_comment->raw() );
		} finally {
			unlink( $tmp );
		}
	}

	public function testRevokedKeyFailsWithRevokedKeyCode(): void {
		$revoked_hex = $this->key()->keyIdHex();

		$verifier = new MinisignVerifier(
			array( $this->key() ),
			static function ( string $key_id_hex ) use ( $revoked_hex ): bool {
				return $key_id_hex === $revoked_hex;
			}
		);

		try {
			$verifier->verifyFile(
				$this->fixture( 'sample-plugin-1.2.3.zip' ),
				$this->signature( 'sample-plugin-1.2.3.zip.minisig' )
			);
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::REVOKED_KEY, $e->errorCode() );
			$this->assertStringContainsString( $revoked_hex, $e->getMessage() );
		}
	}

	public function testRevocationCallableReturningFalseKeepsKeyEffective(): void {
		$verifier = new MinisignVerifier(
			array( $this->key() ),
			static function (): bool {
				return false;
			}
		);

		$comment = $verifier->verifyFile(
			$this->fixture( 'sample-plugin-1.2.3.zip' ),
			$this->signature( 'sample-plugin-1.2.3.zip.minisig' )
		);

		$this->assertSame( 'sample-plugin', $comment->get( 'slug' ) );
	}

	public function testUnknownKeyFailsBeforeTheRevocationCheckRuns(): void {
		// NO_MATCHING_KEY outranks REVOKED_KEY: a key that was never pinned
		// is not "revoked", and the callable must not even be consulted.
		$consulted = false;

		$verifier = new MinisignVerifier(
			array( $this->key() ),
			static function () use ( &$consulted ): bool {
				$consulted = true;

				return true;
			}
		);

		try {
			$verifier->verifyFile(
				$this->fixture( 'sample-plugin-1.2.3.zip' ),
				$this->signature( 'wrong-key.minisig' )
			);
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::NO_MATCHING_KEY, $e->errorCode() );
			$this->assertFalse( $consulted );
		}
	}

	public function testDirectoryPathThrowsUnreadable(): void {
		// fopen() on a directory succeeds on Linux, so this failure surfaces
		// mid-loop when fread() returns false — the second UNREADABLE throw
		// site. PHP raises E_NOTICE/E_WARNING on that fread; absorb it so the
		// suite's failOnWarning doesn't mask the exception under test.
		$verifier = $this->makeVerifier( array( $this->key() ) );

		set_error_handler(
			static function (): bool {
				return true;
			}
		);

		try {
			$verifier->verifyFile(
				sys_get_temp_dir(),
				$this->signature( 'sample-plugin-1.2.3.zip.minisig' )
			);
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::UNREADABLE, $e->errorCode() );
		} finally {
			restore_error_handler();
		}
	}
}
