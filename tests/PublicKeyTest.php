<?php

declare(strict_types=1);

namespace PattonWebz\SignedReleases\Tests;

use PattonWebz\SignedReleases\PublicKey;
use PattonWebz\SignedReleases\VerificationException;
use PHPUnit\Framework\TestCase;

final class PublicKeyTest extends TestCase {

	private function pubFileText(): string {
		return file_get_contents( PATTONWEBZ_TEST_FIXTURES . '/testkey.pub' );
	}

	private function bareBase64(): string {
		$lines = array_values( array_filter( array_map( 'trim', explode( "\n", $this->pubFileText() ) ) ) );

		return $lines[1];
	}

	/** Assert the callable throws MALFORMED with a message substring. */
	private function assertMalformed( callable $parse, string $message_substring ): void {
		try {
			$parse();
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::MALFORMED, $e->errorCode() );
			$this->assertStringContainsString( $message_substring, $e->getMessage() );
		}
	}

	public function testParsesRealMinisignPubFile(): void {
		$text = $this->pubFileText();
		$key  = PublicKey::fromFileText( $text );

		$this->assertSame( 32, strlen( $key->raw() ) );
		$this->assertSame( 8, strlen( $key->keyId() ) );

		// minisign writes its own display-form key ID into the untrusted comment.
		preg_match( '/minisign public key ([0-9A-F]+)/', $text, $m );
		$this->assertSame( $m[1], $key->keyIdHex() );
	}

	public function testParsesBareBase64Form(): void {
		$key = PublicKey::fromBase64( $this->bareBase64() );

		$this->assertSame( PublicKey::fromFileText( $this->pubFileText() )->raw(), $key->raw() );
	}

	public function testRejectsInvalidBase64(): void {
		$this->assertMalformed(
			static function (): void {
				PublicKey::fromBase64( 'not-valid-base64!!!' );
			},
			'not 42 bytes of valid base64'
		);
	}

	public function testRejectsWrongLength(): void {
		$this->assertMalformed(
			static function (): void {
				PublicKey::fromBase64( base64_encode( 'Ed' . str_repeat( 'x', 10 ) ) );
			},
			'not 42 bytes'
		);
	}

	public function testRejectsWrongAlgorithm(): void {
		$this->assertMalformed(
			static function (): void {
				PublicKey::fromBase64( base64_encode( 'XX' . str_repeat( "\0", 40 ) ) );
			},
			'does not use the Ed25519'
		);
	}

	public function testRejectsEmptyText(): void {
		$this->assertMalformed(
			static function (): void {
				PublicKey::fromFileText( "untrusted comment: nothing here\n" );
			},
			'No key material found'
		);
	}

	public function invalidBase64PayloadProvider(): array {
		return array(
			// 41 and 43 raw bytes bracket the exact 42-byte requirement.
			'41 bytes'          => array( base64_encode( 'Ed' . str_repeat( 'x', 39 ) ), 'not 42 bytes' ),
			'43 bytes'          => array( base64_encode( 'Ed' . str_repeat( 'x', 41 ) ), 'not 42 bytes' ),
			// 'ED' is the SIGNATURE prehash tag; public keys only ever use 'Ed'.
			'signature tag ED'  => array( base64_encode( 'ED' . str_repeat( "\0", 40 ) ), 'does not use the Ed25519' ),
			'lowercase tag ed'  => array( base64_encode( 'ed' . str_repeat( "\0", 40 ) ), 'does not use the Ed25519' ),
		);
	}

	/**
	 * @dataProvider invalidBase64PayloadProvider
	 */
	public function testFromBase64RejectsInvalidPayloads( string $base64, string $message_substring ): void {
		$this->assertMalformed(
			static function () use ( $base64 ): void {
				PublicKey::fromBase64( $base64 );
			},
			$message_substring
		);
	}

	public function testFromBase64ToleratesSurroundingWhitespace(): void {
		$key = PublicKey::fromBase64( "  \t" . $this->bareBase64() . " \n" );

		$this->assertSame( PublicKey::fromFileText( $this->pubFileText() )->raw(), $key->raw() );
	}

	public function testFromFileTextThrowsOnJunkFirstLine(): void {
		// The first non-comment, non-blank line is treated as the key — a
		// junk line there fails parsing rather than being skipped over.
		$this->assertMalformed(
			function (): void {
				PublicKey::fromFileText( "garbage line\n" . $this->bareBase64() . "\n" );
			},
			'not 42 bytes'
		);
	}

	public function testFromFileTextHandlesCrlfLineEndings(): void {
		$key = PublicKey::fromFileText( str_replace( "\n", "\r\n", $this->pubFileText() ) );

		$this->assertSame( PublicKey::fromFileText( $this->pubFileText() )->raw(), $key->raw() );
	}

	public function testFromFileTextSkipsMultipleCommentsAndBlankLines(): void {
		$text = "untrusted comment: first comment\n"
			. "\n"
			. "untrusted comment: second comment\n"
			. "\n\n"
			. $this->bareBase64() . "\n";

		$key = PublicKey::fromFileText( $text );

		$this->assertSame( PublicKey::fromFileText( $this->pubFileText() )->raw(), $key->raw() );
	}
}
