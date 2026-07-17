<?php

declare(strict_types=1);

namespace PattonWebz\SignedReleases\Tests;

use PattonWebz\SignedReleases\VerificationException;
use PattonWebz\SignedReleases\VerificationPolicy;
use PHPUnit\Framework\TestCase;

final class VerificationPolicyTest extends TestCase {

	public function modeMatrixProvider(): array {
		// mode, isOff, shouldBlock, shouldLog.
		return array(
			'off'     => array( VerificationPolicy::MODE_OFF, true, false, false ),
			'log'     => array( VerificationPolicy::MODE_LOG, false, false, true ),
			'enforce' => array( VerificationPolicy::MODE_ENFORCE, false, true, true ),
		);
	}

	/**
	 * The full predicate matrix — UpdaterGuard routes every block/log/skip
	 * decision through these three methods.
	 *
	 * @dataProvider modeMatrixProvider
	 */
	public function testModePredicateMatrix( string $mode, bool $is_off, bool $should_block, bool $should_log ): void {
		$policy = new VerificationPolicy( $mode );

		$this->assertSame( $mode, $policy->mode() );
		$this->assertSame( $is_off, $policy->isOff() );
		$this->assertSame( $should_block, $policy->shouldBlock() );
		$this->assertSame( $should_log, $policy->shouldLog() );
	}

	public function invalidModeProvider(): array {
		return array(
			'empty string'       => array( '' ),
			'unknown word'       => array( 'banana' ),
			'uppercase LOG'      => array( 'LOG' ),
			'capitalised Enforce' => array( 'Enforce' ),
			'padded'             => array( ' log' ),
		);
	}

	/**
	 * Modes are matched strictly and case-sensitively: anything else must be
	 * rejected at construction, never silently coerced.
	 *
	 * @dataProvider invalidModeProvider
	 */
	public function testInvalidModesRejectedAtConstruction( string $mode ): void {
		try {
			new VerificationPolicy( $mode );
			$this->fail( 'Expected InvalidArgumentException.' );
		} catch ( \InvalidArgumentException $e ) {
			$this->assertStringContainsString( 'Unknown verification mode', $e->getMessage() );
		}
	}

	public function testVerificationExceptionContract(): void {
		$e = VerificationException::withCode( VerificationException::BAD_SIGNATURE, 'the message' );

		$this->assertSame( 'the message', $e->getMessage() );
		$this->assertSame( VerificationException::BAD_SIGNATURE, $e->errorCode() );

		// RuntimeException parentage: callers may catch broadly.
		$this->assertInstanceOf( \RuntimeException::class, $e );
	}

	public function testVerificationExceptionCodesAreDistinct(): void {
		// The codes are part of the frozen compatibility contract (recorded
		// into shared options read by co-installed copies) — every constant
		// must stay distinct.
		$codes = array(
			VerificationException::MALFORMED,
			VerificationException::NO_MATCHING_KEY,
			VerificationException::BAD_SIGNATURE,
			VerificationException::BAD_GLOBAL_SIGNATURE,
			VerificationException::COMMENT_MISMATCH,
			VerificationException::UNREADABLE,
			VerificationException::MISSING_SIGNATURE,
			VerificationException::MISSING_VERSION,
			VerificationException::DOWNGRADE,
			VerificationException::CRYPTO_UNAVAILABLE,
		);

		$this->assertCount( 10, array_unique( $codes ) );
	}
}
