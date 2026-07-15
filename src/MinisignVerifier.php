<?php
/**
 * Verifies minisign signatures against a set of pinned public keys.
 *
 * Uses the sodium_* functions, which exist on every WordPress >= 5.2 install
 * (natively via ext-sodium, or through the bundled sodium_compat polyfill).
 * The crypto primitives are isolated in protected methods so tests can force
 * the polyfill implementation.
 */

declare(strict_types=1);

namespace PattonWebz\SignedReleases;

class MinisignVerifier {

	private const HASH_BYTES = 64; // BLAKE2b-512, minisign's prehash.
	private const CHUNK_SIZE = 65536;

	/** @var array<string, PublicKey> Keyed by raw 8-byte key ID. */
	private array $keys = array();

	/**
	 * @param PublicKey[] $public_keys Trusted keys. Multiple keys allow rotation:
	 *                                 the signature's key ID selects which is used.
	 */
	public function __construct( array $public_keys ) {
		foreach ( $public_keys as $key ) {
			$this->keys[ $key->keyId() ] = $key;
		}

		if ( empty( $this->keys ) ) {
			throw new \InvalidArgumentException( 'At least one trusted public key is required.' );
		}
	}

	/**
	 * Verify a file on disk against a signature.
	 *
	 * @return TrustedComment The authenticated trusted comment. Callers should
	 *                        follow up with TrustedComment::assertMatches().
	 * @throws VerificationException On any parse or verification failure.
	 */
	public function verifyFile( string $file_path, Signature $signature ): TrustedComment {
		$this->assertCryptoAvailable();
		$key = $this->trustedKeyFor( $signature );

		if ( Signature::ALG_PREHASHED === $signature->algorithm() ) {
			$message = $this->hashFileContents( $file_path );
		} else {
			$message = @file_get_contents( $file_path );

			if ( false === $message ) {
				throw $this->unreadable( $file_path );
			}
		}

		return $this->verifyMessage( $message, $signature, $key );
	}

	/**
	 * Verify in-memory data against a signature.
	 */
	public function verifyString( string $data, Signature $signature ): TrustedComment {
		$this->assertCryptoAvailable();
		$key = $this->trustedKeyFor( $signature );

		if ( Signature::ALG_PREHASHED === $signature->algorithm() ) {
			$state = $this->hashInit();
			$this->hashUpdate( $state, $data );
			$data = $this->hashFinal( $state );
		}

		return $this->verifyMessage( $data, $signature, $key );
	}

	/**
	 * Fail closed if libsodium isn't available at runtime. WordPress >= 5.2
	 * provides these functions natively (ext-sodium) or via the bundled
	 * sodium_compat polyfill; if neither is present we must raise a catchable
	 * exception rather than fatal on an undefined-function call.
	 */
	private function assertCryptoAvailable(): void {
		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' )
			|| ! function_exists( 'sodium_crypto_generichash_init' ) ) {
			throw VerificationException::withCode(
				VerificationException::CRYPTO_UNAVAILABLE,
				'libsodium is unavailable; cannot verify release signatures.'
			);
		}
	}

	private function trustedKeyFor( Signature $signature ): PublicKey {
		$key = $this->keys[ $signature->keyId() ] ?? null;

		if ( null === $key ) {
			throw VerificationException::withCode(
				VerificationException::NO_MATCHING_KEY,
				sprintf(
					'Signature was made with key %s, which is not in the trusted key set.',
					$signature->keyIdHex()
				)
			);
		}

		return $key;
	}

	private function verifyMessage( string $message, Signature $signature, PublicKey $key ): TrustedComment {
		if ( ! $this->verifyDetached( $signature->signature(), $message, $key->raw() ) ) {
			throw VerificationException::withCode(
				VerificationException::BAD_SIGNATURE,
				'File signature verification failed: the file does not match its signature.'
			);
		}

		$global_message = $signature->signature() . $signature->trustedComment();

		if ( ! $this->verifyDetached( $signature->globalSignature(), $global_message, $key->raw() ) ) {
			throw VerificationException::withCode(
				VerificationException::BAD_GLOBAL_SIGNATURE,
				'Global signature verification failed: the trusted comment has been altered.'
			);
		}

		return TrustedComment::parse( $signature->trustedComment() );
	}

	private function hashFileContents( string $file_path ): string {
		$handle = @fopen( $file_path, 'rb' );

		if ( false === $handle ) {
			throw $this->unreadable( $file_path );
		}

		try {
			$state = $this->hashInit();

			while ( ! feof( $handle ) ) {
				$chunk = fread( $handle, self::CHUNK_SIZE );

				if ( false === $chunk ) {
					throw $this->unreadable( $file_path );
				}

				if ( '' !== $chunk ) {
					$this->hashUpdate( $state, $chunk );
				}
			}

			return $this->hashFinal( $state );
		} finally {
			fclose( $handle );
		}
	}

	private function unreadable( string $file_path ): VerificationException {
		return VerificationException::withCode(
			VerificationException::UNREADABLE,
			'Could not read file for verification: ' . $file_path
		);
	}

	// Crypto primitives, overridable in tests to force sodium_compat.

	protected function hashInit(): string {
		return sodium_crypto_generichash_init( '', self::HASH_BYTES );
	}

	protected function hashUpdate( string &$state, string $chunk ): void {
		sodium_crypto_generichash_update( $state, $chunk );
	}

	protected function hashFinal( string &$state ): string {
		return sodium_crypto_generichash_final( $state, self::HASH_BYTES );
	}

	protected function verifyDetached( string $signature, string $message, string $public_key ): bool {
		return sodium_crypto_sign_verify_detached( $signature, $message, $public_key );
	}
}
