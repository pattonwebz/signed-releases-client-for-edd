<?php
/**
 * A parsed key-revocation manifest.
 *
 * The manifest is a small root-signed JSON document naming package-signing
 * key IDs that must no longer be trusted:
 *
 *   {
 *     "format": "pattonwebz-revocation-v1",
 *     "sequence": 3,
 *     "issued_at": "2026-07-18T14:00:00Z",
 *     "revoked_keys": [
 *       { "key_id": "A3C8A30944668DB8", "reason": "ci_secret_compromise",
 *         "revoked_at": "2026-07-18T13:40:00Z" }
 *     ],
 *     "unrevoked_keys": []
 *   }
 *
 * `sequence` is a monotonic integer the client ratchets on (anti-rollback).
 * `unrevoked_keys` is the only way a previously revoked key ever becomes
 * trusted again: client-side revocation state is an append-only union, so
 * merely omitting a key from a later manifest restores nothing. Entries in
 * `unrevoked_keys` use the same shape as `revoked_keys` (key_id required,
 * the rest informational) so a deliberate un-revoke is visible and auditable
 * in the signed artifact itself.
 *
 * Verification of the signature (against the pinned revocation root key, not
 * `public_keys`) happens before this parser runs; this class only validates
 * structure and fails closed on anything it does not recognise.
 */

declare(strict_types=1);

namespace PattonWebz\SignedReleases;

final class RevocationManifest {

	public const FORMAT = 'pattonwebz-revocation-v1';

	private int $sequence;

	/** @var array<string, array{reason: string, revoked_at: string}> Keyed by uppercase hex key ID. */
	private array $revoked;

	/** @var string[] Uppercase hex key IDs explicitly un-revoked by this manifest. */
	private array $unrevoked;

	private function __construct( int $sequence, array $revoked, array $unrevoked ) {
		$this->sequence  = $sequence;
		$this->revoked   = $revoked;
		$this->unrevoked = $unrevoked;
	}

	/**
	 * Parse and structurally validate a manifest JSON body.
	 *
	 * @throws VerificationException MALFORMED on anything unexpected.
	 */
	public static function fromJson( string $json ): self {
		$data = json_decode( $json, true, 8 );

		if ( ! is_array( $data ) ) {
			throw self::malformed( 'Body is not a JSON object.' );
		}

		if ( self::FORMAT !== ( $data['format'] ?? null ) ) {
			throw self::malformed( 'Unknown or missing format tag.' );
		}

		// Strictly an integer >= 1. A string "3" is rejected: the sequence is
		// the anti-rollback ratchet and must never be subject to loose-typed
		// comparison surprises.
		if ( ! isset( $data['sequence'] ) || ! is_int( $data['sequence'] ) || $data['sequence'] < 1 ) {
			throw self::malformed( 'Sequence is not a positive integer.' );
		}

		$revoked   = self::keyEntries( $data['revoked_keys'] ?? array(), 'revoked_keys' );
		$unrevoked = self::keyEntries( $data['unrevoked_keys'] ?? array(), 'unrevoked_keys' );

		// A key both revoked and un-revoked in one manifest is an authoring
		// error; fail closed on the whole artifact rather than guess intent.
		$conflict = array_intersect( array_keys( $revoked ), array_keys( $unrevoked ) );

		if ( array() !== $conflict ) {
			throw self::malformed( 'Key(s) listed as both revoked and unrevoked: ' . implode( ', ', $conflict ) . '.' );
		}

		return new self( $data['sequence'], $revoked, array_keys( $unrevoked ) );
	}

	/**
	 * Validate a revoked_keys / unrevoked_keys list into key_id-keyed entries.
	 *
	 * @param mixed  $entries Raw decoded list.
	 * @param string $field   Field name, for error messages.
	 *
	 * @return array<string, array{reason: string, revoked_at: string}>
	 *
	 * @throws VerificationException MALFORMED on any entry it does not recognise.
	 */
	private static function keyEntries( $entries, string $field ): array {
		if ( ! is_array( $entries ) ) {
			throw self::malformed( $field . ' is not a list.' );
		}

		$parsed = array();

		foreach ( $entries as $entry ) {
			$key_id = is_array( $entry ) ? ( $entry['key_id'] ?? null ) : null;

			// The hex form PublicKey::keyIdHex()/Signature::keyIdHex() produce:
			// 8 bytes as 16 hex digits.
			if ( ! is_string( $key_id ) || 1 !== preg_match( '/^[0-9A-Fa-f]{16}$/', $key_id ) ) {
				throw self::malformed( $field . ' entry has a missing or malformed key_id.' );
			}

			$parsed[ strtoupper( $key_id ) ] = array(
				'reason'     => is_string( $entry['reason'] ?? null ) ? $entry['reason'] : 'unknown',
				'revoked_at' => is_string( $entry['revoked_at'] ?? null ) ? $entry['revoked_at'] : '',
			);
		}

		return $parsed;
	}

	private static function malformed( string $detail ): VerificationException {
		return VerificationException::withCode(
			VerificationException::MALFORMED,
			'Malformed revocation manifest: ' . $detail
		);
	}

	public function sequence(): int {
		return $this->sequence;
	}

	/** @return array<string, array{reason: string, revoked_at: string}> Keyed by uppercase hex key ID. */
	public function revokedKeys(): array {
		return $this->revoked;
	}

	/** @return string[] Uppercase hex key IDs explicitly un-revoked. */
	public function unrevokedKeys(): array {
		return $this->unrevoked;
	}
}
