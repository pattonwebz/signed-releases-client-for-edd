<?php

declare(strict_types=1);

namespace PattonWebz\SignedReleases\Tests;

use PattonWebz\SignedReleases\PublicKey;
use PattonWebz\SignedReleases\VerificationException;
use PHPUnit\Framework\TestCase;

final class PublicKeyTest extends TestCase {

	public function testParsesRealMinisignPubFile(): void {
		$text = file_get_contents( PATTONWEBZ_TEST_FIXTURES . '/testkey.pub' );
		$key  = PublicKey::fromFileText( $text );

		$this->assertSame( 32, strlen( $key->raw() ) );
		$this->assertSame( 8, strlen( $key->keyId() ) );

		// minisign writes its own display-form key ID into the untrusted comment.
		preg_match( '/minisign public key ([0-9A-F]+)/', $text, $m );
		$this->assertSame( $m[1], $key->keyIdHex() );
	}

	public function testParsesBareBase64Form(): void {
		$text  = file_get_contents( PATTONWEBZ_TEST_FIXTURES . '/testkey.pub' );
		$lines = array_values( array_filter( array_map( 'trim', explode( "\n", $text ) ) ) );

		$key = PublicKey::fromBase64( $lines[1] );

		$this->assertSame( PublicKey::fromFileText( $text )->raw(), $key->raw() );
	}

	public function testRejectsInvalidBase64(): void {
		$this->expectException( VerificationException::class );
		PublicKey::fromBase64( 'not-valid-base64!!!' );
	}

	public function testRejectsWrongLength(): void {
		$this->expectException( VerificationException::class );
		PublicKey::fromBase64( base64_encode( 'Ed' . str_repeat( 'x', 10 ) ) );
	}

	public function testRejectsWrongAlgorithm(): void {
		$this->expectException( VerificationException::class );
		PublicKey::fromBase64( base64_encode( 'XX' . str_repeat( "\0", 40 ) ) );
	}

	public function testRejectsEmptyText(): void {
		$this->expectException( VerificationException::class );
		PublicKey::fromFileText( "untrusted comment: nothing here\n" );
	}
}
