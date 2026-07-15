<?php

declare(strict_types=1);

namespace PattonWebz\SignedReleases\Tests;

use PattonWebz\SignedReleases\MinisignVerifier;
use PattonWebz\SignedReleases\PublicKey;
use PattonWebz\SignedReleases\Signature;
use PattonWebz\SignedReleases\VerificationException;
use PHPUnit\Framework\TestCase;

class MinisignVerifierTest extends TestCase {

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

		$this->expectException( VerificationException::class );
		$comment->assertMatches( 'sample-plugin', '1.2.3' );
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

	public function testLegacyRawContentAlgorithmVerifies(): void {
		// Modern minisign only emits prehashed (ED) signatures, so build a
		// legacy (Ed) signature by hand with libsodium to cover that path.
		$keypair = sodium_crypto_sign_keypair();
		$pk      = sodium_crypto_sign_publickey( $keypair );
		$sk      = sodium_crypto_sign_secretkey( $keypair );
		$key_id  = random_bytes( 8 );
		$data    = 'legacy signed content';
		$comment = 'slug:legacy-plugin version:0.1.0';

		$sig        = sodium_crypto_sign_detached( $data, $sk );
		$global_sig = sodium_crypto_sign_detached( $sig . $comment, $sk );

		$minisig = "untrusted comment: legacy test\n"
			. base64_encode( 'Ed' . $key_id . $sig ) . "\n"
			. 'trusted comment: ' . $comment . "\n"
			. base64_encode( $global_sig ) . "\n";

		$public_key = PublicKey::fromBase64( base64_encode( 'Ed' . $key_id . $pk ) );
		$verifier   = $this->makeVerifier( array( $public_key ) );

		$result = $verifier->verifyString( $data, Signature::fromMinisigText( $minisig ) );

		$this->assertSame( 'legacy-plugin', $result->get( 'slug' ) );
	}
}
