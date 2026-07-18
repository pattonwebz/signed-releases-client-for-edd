<?php

declare(strict_types=1);

namespace PattonWebz\SignedReleases\Tests;

use PattonWebz\SignedReleases\RevocationManifest;
use PattonWebz\SignedReleases\VerificationException;
use PHPUnit\Framework\TestCase;

final class RevocationManifestTest extends TestCase {

	private function manifestJson( array $overrides = array() ): string {
		return json_encode(
			array_merge(
				array(
					'format'       => 'pattonwebz-revocation-v1',
					'sequence'     => 3,
					'issued_at'    => '2026-07-18T14:00:00Z',
					'revoked_keys' => array(
						array(
							'key_id'     => 'A3C8A30944668DB8',
							'reason'     => 'ci_secret_compromise',
							'revoked_at' => '2026-07-18T13:40:00Z',
						),
					),
				),
				$overrides
			)
		);
	}

	private function assertMalformed( string $json, string $needle ): void {
		try {
			RevocationManifest::fromJson( $json );
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::MALFORMED, $e->errorCode() );
			$this->assertStringContainsString( $needle, $e->getMessage() );
		}
	}

	public function testValidManifestParses(): void {
		$manifest = RevocationManifest::fromJson( $this->manifestJson() );

		$this->assertSame( 3, $manifest->sequence() );
		$this->assertSame( array( 'A3C8A30944668DB8' ), array_keys( $manifest->revokedKeys() ) );
		$this->assertSame( 'ci_secret_compromise', $manifest->revokedKeys()['A3C8A30944668DB8']['reason'] );
		$this->assertSame( array(), $manifest->unrevokedKeys() );
	}

	public function testKeyIdsAreNormalisedToUppercase(): void {
		$manifest = RevocationManifest::fromJson(
			$this->manifestJson(
				array( 'revoked_keys' => array( array( 'key_id' => 'a3c8a30944668db8' ) ) )
			)
		);

		$this->assertSame( array( 'A3C8A30944668DB8' ), array_keys( $manifest->revokedKeys() ) );
		$this->assertSame( 'unknown', $manifest->revokedKeys()['A3C8A30944668DB8']['reason'] );
	}

	public function testEmptyRevokedListIsValid(): void {
		// A re-issue can legitimately revoke nothing (e.g. only un-revoking).
		$manifest = RevocationManifest::fromJson(
			$this->manifestJson(
				array(
					'revoked_keys'   => array(),
					'unrevoked_keys' => array( array( 'key_id' => 'A3C8A30944668DB8' ) ),
				)
			)
		);

		$this->assertSame( array(), $manifest->revokedKeys() );
		$this->assertSame( array( 'A3C8A30944668DB8' ), $manifest->unrevokedKeys() );
	}

	public function testNonJsonBodyIsRejected(): void {
		$this->assertMalformed( 'not json at all', 'not a JSON object' );
	}

	public function testUnknownFormatTagIsRejected(): void {
		// An incompatible future shape must fail closed at parse.
		$this->assertMalformed( $this->manifestJson( array( 'format' => 'pattonwebz-revocation-v2' ) ), 'format tag' );
		$this->assertMalformed( json_encode( array( 'sequence' => 1 ) ), 'format tag' );
	}

	public function testNonIntegerSequenceIsRejected(): void {
		$this->assertMalformed( $this->manifestJson( array( 'sequence' => '3' ) ), 'positive integer' );
		$this->assertMalformed( $this->manifestJson( array( 'sequence' => 0 ) ), 'positive integer' );
		$this->assertMalformed( $this->manifestJson( array( 'sequence' => -2 ) ), 'positive integer' );
		$this->assertMalformed( $this->manifestJson( array( 'sequence' => null ) ), 'positive integer' );
	}

	public function testMalformedKeyIdIsRejected(): void {
		$this->assertMalformed(
			$this->manifestJson( array( 'revoked_keys' => array( array( 'key_id' => 'XYZ' ) ) ) ),
			'malformed key_id'
		);
		$this->assertMalformed(
			$this->manifestJson( array( 'revoked_keys' => array( array( 'reason' => 'no id' ) ) ) ),
			'malformed key_id'
		);
		$this->assertMalformed(
			$this->manifestJson( array( 'revoked_keys' => array( 'A3C8A30944668DB8' ) ) ),
			'malformed key_id'
		);
	}

	public function testNonListRevokedKeysIsRejected(): void {
		$this->assertMalformed( $this->manifestJson( array( 'revoked_keys' => 'A3C8A30944668DB8' ) ), 'not a list' );
	}

	public function testKeyOnBothListsIsRejected(): void {
		// Revoked AND un-revoked in one artifact is an authoring error; the
		// whole manifest fails closed rather than guessing intent.
		$this->assertMalformed(
			$this->manifestJson(
				array( 'unrevoked_keys' => array( array( 'key_id' => 'a3c8a30944668db8' ) ) )
			),
			'both revoked and unrevoked'
		);
	}
}
