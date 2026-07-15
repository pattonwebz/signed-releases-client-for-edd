<?php

declare(strict_types=1);

namespace PattonWebz\SignedReleases\Tests;

use PattonWebz\SignedReleases\Signature;
use PattonWebz\SignedReleases\VerificationException;
use PHPUnit\Framework\TestCase;

final class SignatureTest extends TestCase {

	private function fixtureText(): string {
		return file_get_contents( PATTONWEBZ_TEST_FIXTURES . '/sample-plugin-1.2.3.zip.minisig' );
	}

	public function testParsesRealMinisigFile(): void {
		$sig = Signature::fromMinisigText( $this->fixtureText() );

		$this->assertSame( Signature::ALG_PREHASHED, $sig->algorithm() );
		$this->assertSame( 8, strlen( $sig->keyId() ) );
		$this->assertSame( 64, strlen( $sig->signature() ) );
		$this->assertSame( 64, strlen( $sig->globalSignature() ) );
		$this->assertSame(
			'slug:sample-plugin version:1.2.3 signed:2026-07-15T00:00:00Z',
			$sig->trustedComment()
		);
		$this->assertSame( 'signature for sample-plugin 1.2.3', $sig->untrustedComment() );
	}

	public function testKeyIdMatchesSigningKey(): void {
		$pub = \PattonWebz\SignedReleases\PublicKey::fromFileText(
			file_get_contents( PATTONWEBZ_TEST_FIXTURES . '/testkey.pub' )
		);
		$sig = Signature::fromMinisigText( $this->fixtureText() );

		$this->assertSame( $pub->keyId(), $sig->keyId() );
	}

	public function testRejectsTruncatedFile(): void {
		$lines = explode( "\n", $this->fixtureText() );

		$this->expectException( VerificationException::class );
		Signature::fromMinisigText( implode( "\n", array_slice( $lines, 0, 2 ) ) );
	}

	public function testRejectsCorruptSignatureLine(): void {
		$lines    = preg_split( '/\R/', $this->fixtureText() );
		$lines[1] = 'AAAA';

		$this->expectException( VerificationException::class );
		Signature::fromMinisigText( implode( "\n", $lines ) );
	}

	public function testRejectsMissingTrustedCommentPrefix(): void {
		$lines    = preg_split( '/\R/', $this->fixtureText() );
		$lines[2] = 'comment without prefix';

		$this->expectException( VerificationException::class );
		Signature::fromMinisigText( implode( "\n", $lines ) );
	}

	public function testRejectsUnknownAlgorithm(): void {
		$lines    = preg_split( '/\R/', $this->fixtureText() );
		$raw      = base64_decode( $lines[1], true );
		$lines[1] = base64_encode( 'ZZ' . substr( $raw, 2 ) );

		$this->expectException( VerificationException::class );
		Signature::fromMinisigText( implode( "\n", $lines ) );
	}

	public function testHandlesWindowsLineEndings(): void {
		$sig = Signature::fromMinisigText( str_replace( "\n", "\r\n", $this->fixtureText() ) );

		$this->assertSame( Signature::ALG_PREHASHED, $sig->algorithm() );
	}
}
