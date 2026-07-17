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

	/** Fixture split into lines for surgical corruption. */
	private function fixtureLines(): array {
		return preg_split( '/\R/', $this->fixtureText() );
	}

	/** Parse $text expecting MALFORMED, optionally pinning a message substring. */
	private function assertMalformed( string $text, ?string $message_substring ): void {
		try {
			Signature::fromMinisigText( $text );
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::MALFORMED, $e->errorCode() );

			if ( null !== $message_substring ) {
				$this->assertStringContainsString( $message_substring, $e->getMessage() );
			}
		}
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

		$this->assertMalformed( implode( "\n", array_slice( $lines, 0, 2 ) ), 'Expected 4 lines' );
	}

	public function testRejectsCorruptSignatureLine(): void {
		// 'AAAA' is valid base64 of the wrong length — this is the length
		// guard, not the base64 one.
		$lines    = $this->fixtureLines();
		$lines[1] = 'AAAA';

		$this->assertMalformed( implode( "\n", $lines ), 'not 74 bytes' );
	}

	public function testRejectsMissingTrustedCommentPrefix(): void {
		$lines    = $this->fixtureLines();
		$lines[2] = 'comment without prefix';

		$this->assertMalformed( implode( "\n", $lines ), 'Third line is not a trusted comment' );
	}

	public function testRejectsUnknownAlgorithm(): void {
		$lines    = $this->fixtureLines();
		$raw      = base64_decode( $lines[1], true );
		$lines[1] = base64_encode( 'ZZ' . substr( $raw, 2 ) );

		$this->assertMalformed( implode( "\n", $lines ), 'Unknown signature algorithm "ZZ"' );
	}

	public function testHandlesWindowsLineEndings(): void {
		$sig = Signature::fromMinisigText( str_replace( "\n", "\r\n", $this->fixtureText() ) );

		$this->assertSame( Signature::ALG_PREHASHED, $sig->algorithm() );
	}

	public function testRejectsLegacyAlgorithm(): void {
		// The 2-byte algorithm tag is covered by neither signature, so it's
		// attacker-selectable on any signature a compromised store serves;
		// accepting it lets the legacy branch be forced open on demand
		// (whole-file read before any check). The pipeline never emits it,
		// so reject outright rather than support an unused, riskier path.
		// Pinning the message proves the DEDICATED legacy branch fired, not
		// the generic unknown-algorithm fallthrough.
		$lines    = $this->fixtureLines();
		$raw      = base64_decode( $lines[1], true );
		$lines[1] = base64_encode( 'Ed' . substr( $raw, 2 ) );

		$this->assertMalformed( implode( "\n", $lines ), 'Legacy (non-prehashed)' );
	}

	public function malformedTextProvider(): array {
		$lines = $this->fixtureLines();
		$raw   = base64_decode( $lines[1], true );

		$with_line = function ( int $index, string $replacement ) use ( $lines ): string {
			$copy           = $lines;
			$copy[ $index ] = $replacement;

			return implode( "\n", $copy );
		};

		return array(
			'empty string'                  => array( '', 'Expected 4 lines' ),
			'single line'                   => array( $lines[0], 'Expected 4 lines' ),
			'three lines'                   => array( implode( "\n", array_slice( $lines, 0, 3 ) ), 'Expected 4 lines' ),
			'html error page'               => array(
				"<html>\n<head><title>503</title></head>\n<body>Service Unavailable</body>\n</html>",
				'First line is not an untrusted comment',
			),
			'utf8 bom before first line'    => array( "\xEF\xBB\xBF" . implode( "\n", $lines ), 'First line is not an untrusted comment' ),
			'lines reordered'               => array( implode( "\n", array( $lines[1], $lines[0], $lines[2], $lines[3] ) ), 'First line is not an untrusted comment' ),
			'73-byte payload'               => array( $with_line( 1, base64_encode( substr( $raw, 0, 73 ) ) ), 'not 74 bytes' ),
			'75-byte payload'               => array( $with_line( 1, base64_encode( $raw . 'x' ) ), 'not 74 bytes' ),
			'invalid base64 signature line' => array( $with_line( 1, substr_replace( $lines[1], '!', 10, 1 ) ), 'not 74 bytes of valid base64' ),
			'63-byte global signature'      => array( $with_line( 3, base64_encode( substr( base64_decode( $lines[3], true ), 0, 63 ) ) ), 'Global signature is not 64 bytes' ),
			'65-byte global signature'      => array( $with_line( 3, base64_encode( base64_decode( $lines[3], true ) . 'x' ) ), 'Global signature is not 64 bytes' ),
			'invalid base64 global line'    => array( $with_line( 3, substr_replace( $lines[3], '!', 10, 1 ) ), 'Global signature is not 64 bytes of valid base64' ),
			'untrusted comment as line 3'   => array(
				// 'untrusted comment:' CONTAINS 'trusted comment:' — the parser
				// must prefix-match, not substring-match.
				$with_line( 2, 'untrusted comment: sneaky' ),
				'Third line is not a trusted comment',
			),
			'lowercase alg tag ed'          => array( $with_line( 1, base64_encode( 'ed' . substr( $raw, 2 ) ) ), 'Unknown signature algorithm' ),
			'mixed-case alg tag eD'         => array( $with_line( 1, base64_encode( 'eD' . substr( $raw, 2 ) ) ), 'Unknown signature algorithm' ),
		);
	}

	/**
	 * @dataProvider malformedTextProvider
	 */
	public function testRejectsMalformedText( string $text, string $message_substring ): void {
		$this->assertMalformed( $text, $message_substring );
	}

	public function testRejectsRandomBytes(): void {
		// Which guard fires depends on where the bytes happen to break the
		// format, so pin only the code here.
		$this->assertMalformed( random_bytes( 64 ), null );
	}

	public function tolerantTextProvider(): array {
		$lines   = $this->fixtureLines();
		$trusted = 'slug:sample-plugin version:1.2.3 signed:2026-07-15T00:00:00Z';

		return array(
			'trailing junk lines ignored'  => array(
				implode( "\n", $lines ) . "\n-----EXTRA-----\ntrailing junk",
				$trusted,
			),
			'interspersed blank lines'     => array(
				$lines[0] . "\n\n" . $lines[1] . "\n\n\n" . $lines[2] . "\n" . $lines[3] . "\n\n",
				$trusted,
			),
			'cr-only line endings'         => array(
				implode( "\r", array_slice( $lines, 0, 4 ) ),
				$trusted,
			),
			'per-line surrounding spaces'  => array(
				'  ' . $lines[0] . "  \n\t" . $lines[1] . "\n " . $lines[2] . " \n" . $lines[3] . '  ',
				$trusted,
			),
			'empty trusted comment'        => array(
				implode( "\n", array( $lines[0], $lines[1], 'trusted comment:', $lines[3] ) ),
				'',
			),
		);
	}

	/**
	 * Parse-level tolerance contract: these variants must all parse, with
	 * the payload fields intact. (Whether they then VERIFY is the crypto
	 * layer's business — e.g. an emptied trusted comment fails the global
	 * signature check downstream.)
	 *
	 * @dataProvider tolerantTextProvider
	 */
	public function testParsesTolerantVariants( string $text, string $expected_trusted ): void {
		$sig = Signature::fromMinisigText( $text );

		$this->assertSame( Signature::ALG_PREHASHED, $sig->algorithm() );
		$this->assertSame( 8, strlen( $sig->keyId() ) );
		$this->assertSame( 64, strlen( $sig->signature() ) );
		$this->assertSame( 64, strlen( $sig->globalSignature() ) );
		$this->assertSame( $expected_trusted, $sig->trustedComment() );
	}
}
