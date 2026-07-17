<?php

declare(strict_types=1);

namespace PattonWebz\SignedReleases\Tests;

/**
 * Builds real minisign-format signatures in-test with ext-sodium, so tests can
 * exercise scenarios the committed fixtures cannot (custom trusted comments,
 * genuinely stale signatures over different bytes, arbitrary payload sizes)
 * without shipping new fixtures or requiring the minisign binary.
 *
 * Mirrors the signing pipeline: Ed25519 over the BLAKE2b-512 prehash of the
 * data (algorithm tag "ED"), plus the global signature over
 * signature || trusted comment.
 */
trait InTestSigner {

	/**
	 * @return array{secret: string, public_b64: string, key_id: string}
	 *               Secret key, the bare-base64 public key form UpdaterGuard
	 *               and PublicKey::fromBase64() accept, and the raw key ID.
	 */
	protected function makeSignerKeypair(): array {
		$keypair = sodium_crypto_sign_keypair();
		$key_id  = random_bytes( 8 );

		return array(
			'secret'     => sodium_crypto_sign_secretkey( $keypair ),
			'public_b64' => base64_encode( 'Ed' . $key_id . sodium_crypto_sign_publickey( $keypair ) ),
			'key_id'     => $key_id,
		);
	}

	/**
	 * Produce a complete 4-line .minisig text over $data.
	 *
	 * @param array  $keypair         From makeSignerKeypair().
	 * @param string $data            Raw bytes being signed (prehashed here).
	 * @param string $trusted_comment Trusted comment covered by the global signature.
	 */
	protected function signMinisig( array $keypair, string $data, string $trusted_comment ): string {
		$prehash    = sodium_crypto_generichash( $data, '', 64 );
		$sig        = sodium_crypto_sign_detached( $prehash, $keypair['secret'] );
		$global_sig = sodium_crypto_sign_detached( $sig . $trusted_comment, $keypair['secret'] );

		return "untrusted comment: in-test signature\n"
			. base64_encode( 'ED' . $keypair['key_id'] . $sig ) . "\n"
			. 'trusted comment: ' . $trusted_comment . "\n"
			. base64_encode( $global_sig ) . "\n";
	}
}
