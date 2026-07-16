<?php
/**
 * A parsed .minisig signature file.
 *
 * File format (4 lines):
 *   untrusted comment: <anything>
 *   base64( alg(2) + key_id(8) + signature(64) )
 *   trusted comment: <anything, covered by the global signature>
 *   base64( global_signature(64) )  — Ed25519 over signature || trusted comment
 */

declare(strict_types=1);

namespace PattonWebz\SignedReleases;

final class Signature {

	/** Modern minisign: Ed25519 over the BLAKE2b-512 hash of the file. */
	public const ALG_PREHASHED = 'ED';

	/** Legacy minisign: Ed25519 over the raw file contents. */
	public const ALG_LEGACY = 'Ed';

	private string $algorithm;
	private string $keyId;
	private string $signature;
	private string $trustedComment;
	private string $globalSignature;
	private string $untrustedComment;

	private function __construct(
		string $algorithm,
		string $key_id,
		string $signature,
		string $trusted_comment,
		string $global_signature,
		string $untrusted_comment
	) {
		$this->algorithm        = $algorithm;
		$this->keyId            = $key_id;
		$this->signature        = $signature;
		$this->trustedComment   = $trusted_comment;
		$this->globalSignature  = $global_signature;
		$this->untrustedComment = $untrusted_comment;
	}

	public static function fromMinisigText( string $text ): self {
		$lines = array_values(
			array_filter(
				array_map( 'trim', preg_split( '/\R/', $text ) ),
				static function ( string $line ): bool {
					return '' !== $line;
				}
			)
		);

		if ( count( $lines ) < 4 ) {
			throw self::malformed( 'Expected 4 lines, got ' . count( $lines ) . '.' );
		}

		if ( 0 !== strpos( $lines[0], 'untrusted comment:' ) ) {
			throw self::malformed( 'First line is not an untrusted comment.' );
		}
		$untrusted = ltrim( substr( $lines[0], strlen( 'untrusted comment:' ) ) );

		$sig_raw = base64_decode( $lines[1], true );
		if ( false === $sig_raw || 74 !== strlen( $sig_raw ) ) {
			throw self::malformed( 'Signature payload is not 74 bytes of valid base64.' );
		}

		$algorithm = substr( $sig_raw, 0, 2 );
		if ( self::ALG_LEGACY === $algorithm ) {
			// The 2-byte algorithm tag is covered by neither the file signature
			// nor the global signature, so it's attacker-selectable on any
			// signature a compromised store serves — flipping it forces the
			// legacy path to read the entire (attacker-sized) file into memory
			// before any Ed25519 check runs, a memory-exhaustion DoS. The
			// signing pipeline only ever emits ALG_PREHASHED, so reject legacy
			// outright rather than support a path nothing legitimate uses.
			throw self::malformed( 'Legacy (non-prehashed) minisign signatures are not supported; only the modern prehashed algorithm is accepted.' );
		}
		if ( self::ALG_PREHASHED !== $algorithm ) {
			throw self::malformed( 'Unknown signature algorithm "' . $algorithm . '".' );
		}

		if ( 0 !== strpos( $lines[2], 'trusted comment:' ) ) {
			throw self::malformed( 'Third line is not a trusted comment.' );
		}
		$trusted = ltrim( substr( $lines[2], strlen( 'trusted comment:' ) ) );

		$global_raw = base64_decode( $lines[3], true );
		if ( false === $global_raw || 64 !== strlen( $global_raw ) ) {
			throw self::malformed( 'Global signature is not 64 bytes of valid base64.' );
		}

		return new self(
			$algorithm,
			substr( $sig_raw, 2, 8 ),
			substr( $sig_raw, 10, 64 ),
			$trusted,
			$global_raw,
			$untrusted
		);
	}

	private static function malformed( string $detail ): VerificationException {
		return VerificationException::withCode(
			VerificationException::MALFORMED,
			'Malformed minisign signature: ' . $detail
		);
	}

	public function algorithm(): string {
		return $this->algorithm;
	}

	/** Raw 8-byte key ID of the key that produced this signature. */
	public function keyId(): string {
		return $this->keyId;
	}

	public function keyIdHex(): string {
		return strtoupper( bin2hex( strrev( $this->keyId ) ) );
	}

	/** Raw 64-byte Ed25519 signature over the file (or its BLAKE2b-512 hash). */
	public function signature(): string {
		return $this->signature;
	}

	public function trustedComment(): string {
		return $this->trustedComment;
	}

	/** Raw 64-byte Ed25519 signature over signature || trusted comment. */
	public function globalSignature(): string {
		return $this->globalSignature;
	}

	public function untrustedComment(): string {
		return $this->untrustedComment;
	}
}
