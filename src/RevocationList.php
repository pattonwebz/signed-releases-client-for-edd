<?php
/**
 * The durable, append-only cache of revoked package-signing key IDs.
 *
 * Semantics (the load-bearing part):
 *  - Union, not replace: applying a manifest ADDS its revoked keys to the
 *    cache. A later manifest that merely omits a previously revoked key
 *    changes nothing — an operator hand-editing manifest JSON during an
 *    incident cannot silently re-trust a stolen key by forgetting a line.
 *    The only way back to trusted is an explicit `unrevoked_keys` entry in
 *    a newer root-signed manifest.
 *  - Sequence ratchet: only a manifest with a strictly higher sequence than
 *    the cache is applied. Equal is a no-op; lower is a rollback attempt
 *    (or a stale replay) and is rejected.
 *  - Not slug-keyed, but scoped to the pinned revocation root: a stolen CI
 *    secret plausibly signs for every product a shop ships, so revocation
 *    state is shared by every guard that pins the SAME root key. It is *not*
 *    shared across different roots — this package ships un-prefixed and its
 *    first-loaded copy serves every co-installed plugin (see UpdaterGuard's
 *    compatibility contract), so an unrelated vendor's guard, pinning a
 *    different root, must not be able to revoke this shop's keys. The option
 *    holds one bucket per root scope; a guard only ever reads and writes its
 *    own scope. Same-shop sharing (the design intent) is preserved because
 *    same-shop guards pin the same root; cross-vendor poisoning is not.
 *
 * Honest residual (documented, not solved): this cache lives in an option.
 * An option wipe resets it to empty, re-trusting every pinned key until the
 * next successful manifest fetch. Unlike the downgrade floor there is no
 * code-resident backstop — a baked-in snapshot could only cover keys revoked
 * before that build shipped, which is false confidence, not protection.
 */

declare(strict_types=1);

namespace PattonWebz\SignedReleases;

final class RevocationList {

	/*
	 * Part of the shared-copy compatibility contract (see UpdaterGuard):
	 * the option name and its array shape are frozen once shipped.
	 * Shape: array<string scope, array{sequence: int, revoked: array<string, array{reason: string, revoked_at: string}>}>
	 * — an outer map keyed by root scope, each bucket keyed by uppercase hex
	 * key ID. The scope is an opaque per-root string set by the caller.
	 */
	public const OPTION_REVOCATIONS = 'pattonwebz_signed_releases_revocations';

	public const APPLY_ACCEPTED = 'accepted';
	public const APPLY_NOOP     = 'noop';
	public const APPLY_ROLLBACK = 'rollback';

	/** Bucket used when no scope is supplied (direct/standalone use). */
	private const DEFAULT_SCOPE = 'default';

	/** Opaque per-root scope this instance reads and writes. */
	private string $scope;

	/**
	 * @param string $scope Opaque identifier for the pinned revocation root
	 *                      (UpdaterGuard passes the root key's fingerprint).
	 *                      Guards pinning different roots get isolated buckets;
	 *                      an empty scope falls back to a shared default bucket
	 *                      for standalone use and tests.
	 */
	public function __construct( string $scope = self::DEFAULT_SCOPE ) {
		$this->scope = '' !== $scope ? $scope : self::DEFAULT_SCOPE;
	}

	/**
	 * Whether a signing key ID is revoked.
	 *
	 * @param string $key_id_hex Key ID in the hex form Signature::keyIdHex() produces.
	 */
	public function isRevoked( string $key_id_hex ): bool {
		$state = $this->state();

		return isset( $state['revoked'][ strtoupper( $key_id_hex ) ] );
	}

	/** The highest manifest sequence this site has accepted; 0 when none. */
	public function sequence(): int {
		return $this->state()['sequence'];
	}

	/** @return array<string, array{reason: string, revoked_at: string}> */
	public function revokedKeys(): array {
		return $this->state()['revoked'];
	}

	/**
	 * Merge a verified manifest into the cache.
	 *
	 * Callers must have verified the manifest signature against the pinned
	 * revocation root before calling this — the list never sees raw bytes.
	 *
	 * @return string One of the APPLY_* outcomes.
	 */
	public function apply( RevocationManifest $manifest ): string {
		$state = $this->state();

		if ( $manifest->sequence() < $state['sequence'] ) {
			return self::APPLY_ROLLBACK;
		}

		if ( $manifest->sequence() === $state['sequence'] ) {
			return self::APPLY_NOOP;
		}

		// Union: existing revocations persist unless explicitly un-revoked.
		// (The manifest parser already rejected any key listed on both sides.)
		// The + operator, not array_merge(): an all-digit hex key ID ("1234…")
		// becomes an *integer* array key under PHP's coercion, and array_merge
		// RENUMBERS integer keys — silently discarding that revocation.
		$revoked = $state['revoked'] + $manifest->revokedKeys();

		foreach ( $manifest->unrevokedKeys() as $key_id_hex ) {
			unset( $revoked[ $key_id_hex ] );
		}

		$this->persist(
			array(
				'sequence' => $manifest->sequence(),
				'revoked'  => $revoked,
			)
		);

		return self::APPLY_ACCEPTED;
	}

	/**
	 * Current cache state, normalised. A corrupt or scalar option value (a
	 * bad migration, another plugin's write) degrades to the empty state
	 * rather than fataling — the same posture as the guard's other options.
	 *
	 * @return array{sequence: int, revoked: array<string, array{reason: string, revoked_at: string}>}
	 */
	private function state(): array {
		$empty = array(
			'sequence' => 0,
			'revoked'  => array(),
		);

		$bucket = $this->bucket();

		if ( null === $bucket ) {
			return $empty;
		}

		$sequence = ( isset( $bucket['sequence'] ) && is_int( $bucket['sequence'] ) && $bucket['sequence'] > 0 )
			? $bucket['sequence']
			: 0;

		$revoked = array();

		if ( isset( $bucket['revoked'] ) && is_array( $bucket['revoked'] ) ) {
			foreach ( $bucket['revoked'] as $key_id => $entry ) {
				// Cast before validating: an all-digit hex key ID was coerced
				// to an integer array key when stored; dropping it here would
				// silently fail open for exactly that key.
				$key_id = (string) $key_id;

				if ( 1 !== preg_match( '/^[0-9A-F]{16}$/', $key_id ) ) {
					continue;
				}

				$revoked[ $key_id ] = array(
					'reason'     => is_string( $entry['reason'] ?? null ) ? $entry['reason'] : 'unknown',
					'revoked_at' => is_string( $entry['revoked_at'] ?? null ) ? $entry['revoked_at'] : '',
				);
			}
		}

		return array(
			'sequence' => $sequence,
			'revoked'  => $revoked,
		);
	}

	/**
	 * This instance's scope bucket from the stored option, or null when the
	 * option is missing/corrupt/absent for this scope. A scalar or otherwise
	 * malformed option degrades to null (empty state) rather than fataling.
	 *
	 * The stored shape is scope-keyed. A legacy flat shape (a top-level
	 * `sequence`/`revoked`, from before scoping) is deliberately ignored, not
	 * migrated: nothing has shipped with the flat shape, and reading it into
	 * every scope would reintroduce exactly the cross-root bleed scoping
	 * exists to prevent.
	 *
	 * @return array<string, mixed>|null
	 */
	private function bucket(): ?array {
		if ( ! function_exists( 'get_option' ) ) {
			return null;
		}

		$stored = get_option( self::OPTION_REVOCATIONS, array() );

		if ( ! is_array( $stored ) || ! isset( $stored[ $this->scope ] ) || ! is_array( $stored[ $this->scope ] ) ) {
			return null;
		}

		return $stored[ $this->scope ];
	}

	private function persist( array $state ): void {
		if ( ! function_exists( 'get_option' ) || ! function_exists( 'update_option' ) ) {
			return;
		}

		$stored = get_option( self::OPTION_REVOCATIONS, array() );

		if ( ! is_array( $stored ) ) {
			$stored = array();
		}

		// Write only this instance's scope bucket, leaving every other root's
		// bucket untouched.
		$stored[ $this->scope ] = $state;

		update_option( self::OPTION_REVOCATIONS, $stored, false );
	}
}
