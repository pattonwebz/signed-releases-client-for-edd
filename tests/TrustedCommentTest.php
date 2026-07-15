<?php

declare(strict_types=1);

namespace PattonWebz\SignedReleases\Tests;

use PattonWebz\SignedReleases\TrustedComment;
use PattonWebz\SignedReleases\VerificationException;
use PHPUnit\Framework\TestCase;

final class TrustedCommentTest extends TestCase {

	public function testParsesKeyValueTokens(): void {
		$comment = TrustedComment::parse( 'slug:sample-plugin version:1.2.3 signed:2026-07-15T00:00:00Z' );

		$this->assertSame( 'sample-plugin', $comment->get( 'slug' ) );
		$this->assertSame( '1.2.3', $comment->get( 'version' ) );
		$this->assertSame( '2026-07-15T00:00:00Z', $comment->get( 'signed' ) );
		$this->assertNull( $comment->get( 'missing' ) );
	}

	public function testFirstOccurrenceWinsOnDuplicateKeys(): void {
		$comment = TrustedComment::parse( 'slug:real-plugin slug:evil-plugin' );

		$this->assertSame( 'real-plugin', $comment->get( 'slug' ) );
	}

	public function testIgnoresTokensWithoutColon(): void {
		$comment = TrustedComment::parse( 'timestamp 12345 slug:thing' );

		$this->assertSame( 'thing', $comment->get( 'slug' ) );
	}

	public function testAssertMatchesPasses(): void {
		$comment = TrustedComment::parse( 'slug:sample-plugin version:1.2.3' );

		$comment->assertMatches( 'sample-plugin', '1.2.3' );
		$this->addToAssertionCount( 1 );
	}

	public function testAssertMatchesSkipsNullExpectations(): void {
		$comment = TrustedComment::parse( 'slug:sample-plugin version:1.2.3' );

		$comment->assertMatches( 'sample-plugin', null );
		$comment->assertMatches( null, '1.2.3' );
		$this->addToAssertionCount( 1 );
	}

	public function testAssertMatchesRejectsWrongSlug(): void {
		$comment = TrustedComment::parse( 'slug:evil-plugin version:1.2.3' );

		try {
			$comment->assertMatches( 'sample-plugin', '1.2.3' );
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::COMMENT_MISMATCH, $e->errorCode() );
		}
	}

	public function testAssertMatchesRejectsWrongVersion(): void {
		$comment = TrustedComment::parse( 'slug:sample-plugin version:9.9.9' );

		try {
			$comment->assertMatches( 'sample-plugin', '1.2.3' );
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::COMMENT_MISMATCH, $e->errorCode() );
		}
	}

	public function testAssertMatchesRejectsMissingField(): void {
		$comment = TrustedComment::parse( 'just a freeform comment' );

		$this->expectException( VerificationException::class );
		$comment->assertMatches( 'sample-plugin', null );
	}
}
