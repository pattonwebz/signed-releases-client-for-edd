<?php
/**
 * What to do when a release fails (or is missing) signature verification.
 *
 * Rollout intent: ship in "log" mode first, flip to "enforce" once signing
 * has proven reliable across a release cycle. "off" exists as a kill switch.
 */

declare(strict_types=1);

namespace PattonWebz\SignedReleases;

final class VerificationPolicy {

	public const MODE_OFF     = 'off';
	public const MODE_LOG     = 'log';
	public const MODE_ENFORCE = 'enforce';

	private string $mode;

	public function __construct( string $mode ) {
		if ( ! in_array( $mode, array( self::MODE_OFF, self::MODE_LOG, self::MODE_ENFORCE ), true ) ) {
			throw new \InvalidArgumentException( 'Unknown verification mode: ' . $mode );
		}

		$this->mode = $mode;
	}

	public function mode(): string {
		return $this->mode;
	}

	public function isOff(): bool {
		return self::MODE_OFF === $this->mode;
	}

	/** Should a failure block the install? */
	public function shouldBlock(): bool {
		return self::MODE_ENFORCE === $this->mode;
	}

	/** Should a failure be recorded/surfaced? (log and enforce both do) */
	public function shouldLog(): bool {
		return self::MODE_OFF !== $this->mode;
	}
}
