<?php
/**
 * Thrown when a release signature fails to parse or verify.
 */

declare(strict_types=1);

namespace PattonWebz\SignedReleases;

final class VerificationException extends \RuntimeException {

	public const MALFORMED            = 'malformed';
	public const NO_MATCHING_KEY      = 'no_matching_key';
	public const BAD_SIGNATURE        = 'bad_signature';
	public const BAD_GLOBAL_SIGNATURE = 'bad_global_signature';
	public const COMMENT_MISMATCH     = 'comment_mismatch';
	public const UNREADABLE           = 'unreadable';

	private string $errorCode;

	public static function withCode( string $error_code, string $message ): self {
		$e            = new self( $message );
		$e->errorCode = $error_code;

		return $e;
	}

	public function errorCode(): string {
		return $this->errorCode;
	}
}
