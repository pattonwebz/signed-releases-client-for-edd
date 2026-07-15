<?php
/**
 * The trusted comment our release pipeline signs into every .minisig:
 * whitespace-separated key:value tokens, e.g.
 *
 *   slug:sample-plugin version:1.2.3 signed:2026-07-15T00:00:00Z
 *
 * Because the trusted comment is covered by minisign's global signature,
 * matching it against the expected slug/version prevents an attacker from
 * replaying a validly-signed zip of a different plugin or an older version.
 */

declare(strict_types=1);

namespace PattonWebz\SignedReleases;

final class TrustedComment {

	private string $raw;

	/** @var array<string, string> */
	private array $fields;

	private function __construct( string $raw, array $fields ) {
		$this->raw    = $raw;
		$this->fields = $fields;
	}

	public static function parse( string $raw ): self {
		$fields = array();

		foreach ( preg_split( '/\s+/', trim( $raw ) ) as $token ) {
			$pos = strpos( $token, ':' );

			if ( false === $pos || 0 === $pos ) {
				continue;
			}

			$key = substr( $token, 0, $pos );

			// First occurrence wins; later duplicates cannot override.
			if ( ! isset( $fields[ $key ] ) ) {
				$fields[ $key ] = substr( $token, $pos + 1 );
			}
		}

		return new self( $raw, $fields );
	}

	public function raw(): string {
		return $this->raw;
	}

	public function get( string $key ): ?string {
		return $this->fields[ $key ] ?? null;
	}

	/**
	 * Assert the comment identifies the release we intend to install.
	 * Pass null to skip a check (e.g. when the expected version is unknown).
	 *
	 * @throws VerificationException When a supplied expectation is missing or differs.
	 */
	public function assertMatches( ?string $expected_slug, ?string $expected_version ): void {
		if ( null !== $expected_slug && $this->get( 'slug' ) !== $expected_slug ) {
			throw VerificationException::withCode(
				VerificationException::COMMENT_MISMATCH,
				sprintf(
					'Signature is for plugin "%s", expected "%s".',
					$this->get( 'slug' ) ?? '(missing)',
					$expected_slug
				)
			);
		}

		if ( null !== $expected_version && $this->get( 'version' ) !== $expected_version ) {
			throw VerificationException::withCode(
				VerificationException::COMMENT_MISMATCH,
				sprintf(
					'Signature is for version "%s", expected "%s".',
					$this->get( 'version' ) ?? '(missing)',
					$expected_version
				)
			);
		}
	}
}
