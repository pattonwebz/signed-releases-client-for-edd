<?php

declare(strict_types=1);

namespace PattonWebz\SignedReleases\Tests;

use ParagonIE_Sodium_Compat;
use PattonWebz\SignedReleases\MinisignVerifier;

/**
 * Re-runs the entire verifier suite through paragonie/sodium_compat's pure-PHP
 * implementations, proving verification works on hosts without ext-sodium
 * (WordPress >= 5.2 ships this polyfill).
 */
final class SodiumCompatVerifierTest extends MinisignVerifierTest {

	protected function setUp(): void {
		// Without this, sodium_compat silently delegates to ext-sodium when
		// it's loaded and we'd only be testing the native path twice.
		ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = true;
	}

	protected function tearDown(): void {
		ParagonIE_Sodium_Compat::$disableFallbackForUnitTests = false;
	}

	protected function makeVerifier( array $keys ): MinisignVerifier {
		return new class( $keys ) extends MinisignVerifier {

			protected function hashInit(): string {
				return ParagonIE_Sodium_Compat::crypto_generichash_init( '', 64 );
			}

			protected function hashUpdate( string &$state, string $chunk ): void {
				ParagonIE_Sodium_Compat::crypto_generichash_update( $state, $chunk );
			}

			protected function hashFinal( string &$state ): string {
				return ParagonIE_Sodium_Compat::crypto_generichash_final( $state, 64 );
			}

			protected function verifyDetached( string $signature, string $message, string $public_key ): bool {
				return ParagonIE_Sodium_Compat::crypto_sign_verify_detached( $signature, $message, $public_key );
			}
		};
	}
}
