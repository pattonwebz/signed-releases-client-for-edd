<?php
/**
 * A parsed minisign public key.
 *
 * File format: an "untrusted comment:" line followed by base64 of
 * "Ed" + key_id(8 bytes) + Ed25519 public key(32 bytes).
 */

declare(strict_types=1);

namespace PattonWebz\SignedReleases;

final class PublicKey {

	private const ALGORITHM = 'Ed';

	/** Raw 8-byte key identifier. */
	private string $keyId;

	/** Raw 32-byte Ed25519 public key. */
	private string $rawKey;

	private function __construct( string $key_id, string $raw_key ) {
		$this->keyId  = $key_id;
		$this->rawKey = $raw_key;
	}

	/**
	 * Parse the base64 payload of a minisign public key (the single-line
	 * form used with `minisign -P`).
	 */
	public static function fromBase64( string $base64 ): self {
		$raw = base64_decode( trim( $base64 ), true );

		if ( false === $raw || 42 !== strlen( $raw ) ) {
			throw VerificationException::withCode(
				VerificationException::MALFORMED,
				'Public key is not 42 bytes of valid base64.'
			);
		}

		if ( self::ALGORITHM !== substr( $raw, 0, 2 ) ) {
			throw VerificationException::withCode(
				VerificationException::MALFORMED,
				'Public key does not use the Ed25519 (Ed) algorithm.'
			);
		}

		return new self( substr( $raw, 2, 8 ), substr( $raw, 10, 32 ) );
	}

	/**
	 * Parse a full minisign.pub file (untrusted comment line + base64 line).
	 */
	public static function fromFileText( string $text ): self {
		foreach ( preg_split( '/\R/', $text ) as $line ) {
			$line = trim( $line );

			if ( '' === $line || 0 === strpos( $line, 'untrusted comment:' ) ) {
				continue;
			}

			return self::fromBase64( $line );
		}

		throw VerificationException::withCode(
			VerificationException::MALFORMED,
			'No key material found in public key text.'
		);
	}

	/** Raw 8-byte key ID as found in signatures. */
	public function keyId(): string {
		return $this->keyId;
	}

	/** Key ID in the hex form minisign prints (little-endian uint64). */
	public function keyIdHex(): string {
		return strtoupper( bin2hex( strrev( $this->keyId ) ) );
	}

	/** Raw 32-byte Ed25519 public key. */
	public function raw(): string {
		return $this->rawKey;
	}
}
