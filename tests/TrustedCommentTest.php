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

	public function testEmptyCommentParsesAndFailsMatchWithMissingMarker(): void {
		$comment = TrustedComment::parse( '' );

		$this->assertSame( '', $comment->raw() );
		$this->assertNull( $comment->get( 'slug' ) );

		try {
			$comment->assertMatches( 'sample-plugin', null );
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::COMMENT_MISMATCH, $e->errorCode() );
			$this->assertStringContainsString( '(missing)', $e->getMessage() );
		}
	}

	public function testValuelessTokenParsesAsEmptyStringNotNull(): void {
		// 'version:' with no value is a PRESENT-but-empty field. The guard
		// depends on the distinction: '' routes to missing_version, while a
		// null would mean the token wasn't there at all.
		$comment = TrustedComment::parse( 'slug:sample-plugin version:' );

		$this->assertSame( '', $comment->get( 'version' ) );
		$this->assertNotNull( $comment->get( 'version' ) );
	}

	public function testTokenStartingWithColonIsIgnored(): void {
		// ':value' has no key; it must not create a field keyed ''.
		$comment = TrustedComment::parse( ':orphan slug:sample-plugin' );

		$this->assertNull( $comment->get( '' ) );
		$this->assertSame( 'sample-plugin', $comment->get( 'slug' ) );
	}

	public function testTabAndMultiSpaceSeparatorsSplitTokens(): void {
		$comment = TrustedComment::parse( "slug:sample-plugin\tversion:1.2.3   signed:2026-07-15T00:00:00Z" );

		$this->assertSame( 'sample-plugin', $comment->get( 'slug' ) );
		$this->assertSame( '1.2.3', $comment->get( 'version' ) );
		$this->assertSame( '2026-07-15T00:00:00Z', $comment->get( 'signed' ) );
	}

	public function testVersionMatchIsStrictStringInequalityNotVersionCompare(): void {
		// assertMatches() pins the exact signed string: '01.2.3' is the same
		// release as '1.2.3' to version_compare(), but NOT to the comment
		// binding — normalisation games must not slip past the match.
		$comment = TrustedComment::parse( 'slug:sample-plugin version:01.2.3' );

		try {
			$comment->assertMatches( 'sample-plugin', '1.2.3' );
			$this->fail( 'Expected VerificationException.' );
		} catch ( VerificationException $e ) {
			$this->assertSame( VerificationException::COMMENT_MISMATCH, $e->errorCode() );
			$this->assertStringContainsString( '01.2.3', $e->getMessage() );
		}
	}
}
