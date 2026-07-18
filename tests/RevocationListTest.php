<?php

declare(strict_types=1);

namespace PattonWebz\SignedReleases\Tests;

use PattonWebz\SignedReleases\RevocationList;
use PattonWebz\SignedReleases\RevocationManifest;
use PHPUnit\Framework\TestCase;

final class RevocationListTest extends TestCase {

	private const KEY_A = 'A3C8A30944668DB8';
	private const KEY_B = 'B7E1000000000001';

	protected function setUp(): void {
		wp_shims_reset();
	}

	private function manifest( int $sequence, array $revoked = array(), array $unrevoked = array() ): RevocationManifest {
		$entry = static function ( string $key_id ): array {
			return array( 'key_id' => $key_id );
		};

		return RevocationManifest::fromJson(
			json_encode(
				array(
					'format'         => 'pattonwebz-revocation-v1',
					'sequence'       => $sequence,
					'revoked_keys'   => array_map( $entry, $revoked ),
					'unrevoked_keys' => array_map( $entry, $unrevoked ),
				)
			)
		);
	}

	public function testEmptyStateRevokesNothing(): void {
		$list = new RevocationList();

		$this->assertFalse( $list->isRevoked( self::KEY_A ) );
		$this->assertSame( 0, $list->sequence() );
		$this->assertSame( array(), $list->revokedKeys() );
	}

	public function testAcceptedManifestRevokesAndRatchets(): void {
		$list = new RevocationList();

		$this->assertSame( RevocationList::APPLY_ACCEPTED, $list->apply( $this->manifest( 1, array( self::KEY_A ) ) ) );
		$this->assertTrue( $list->isRevoked( self::KEY_A ) );
		$this->assertFalse( $list->isRevoked( self::KEY_B ) );
		$this->assertSame( 1, $list->sequence() );
	}

	public function testIsRevokedIsCaseInsensitive(): void {
		$list = new RevocationList();
		$list->apply( $this->manifest( 1, array( self::KEY_A ) ) );

		$this->assertTrue( $list->isRevoked( strtolower( self::KEY_A ) ) );
	}

	public function testStatePersistsAcrossInstances(): void {
		( new RevocationList() )->apply( $this->manifest( 1, array( self::KEY_A ) ) );

		$this->assertTrue( ( new RevocationList() )->isRevoked( self::KEY_A ) );
	}

	public function testEqualSequenceIsNoop(): void {
		$list = new RevocationList();
		$list->apply( $this->manifest( 2, array( self::KEY_A ) ) );

		$this->assertSame( RevocationList::APPLY_NOOP, $list->apply( $this->manifest( 2, array( self::KEY_B ) ) ) );
		$this->assertFalse( $list->isRevoked( self::KEY_B ) );
	}

	public function testLowerSequenceIsRollbackAndChangesNothing(): void {
		$list = new RevocationList();
		$list->apply( $this->manifest( 3, array( self::KEY_A ) ) );

		$this->assertSame( RevocationList::APPLY_ROLLBACK, $list->apply( $this->manifest( 2, array(), array( self::KEY_A ) ) ) );
		$this->assertTrue( $list->isRevoked( self::KEY_A ) );
		$this->assertSame( 3, $list->sequence() );
	}

	public function testOmissionDoesNotUnrevoke(): void {
		// The append-only union: a later manifest that merely OMITS a
		// previously revoked key restores nothing. Hand-editing manifest #4
		// and forgetting a line from #3 must be a no-op, not a silent
		// re-trust of a stolen key.
		$list = new RevocationList();
		$list->apply( $this->manifest( 1, array( self::KEY_A ) ) );
		$list->apply( $this->manifest( 2, array( self::KEY_B ) ) );

		$this->assertTrue( $list->isRevoked( self::KEY_A ) );
		$this->assertTrue( $list->isRevoked( self::KEY_B ) );
	}

	public function testNoopAndRollbackLeaveTheStoredOptionByteIdentical(): void {
		// Invariant: a noop (equal sequence) and a rollback (lower sequence)
		// must not mutate ANY of the persisted state — not just the spot-
		// checked keys, but the whole option value, metadata included.
		$list = new RevocationList();
		$list->apply( $this->manifest( 3, array( self::KEY_A ) ) );

		$before = get_option( RevocationList::OPTION_REVOCATIONS );

		// Equal sequence carrying a different key: noop.
		$this->assertSame( RevocationList::APPLY_NOOP, $list->apply( $this->manifest( 3, array( self::KEY_B ) ) ) );
		$this->assertSame( $before, get_option( RevocationList::OPTION_REVOCATIONS ) );

		// Lower sequence attempting to un-revoke KEY_A: rollback.
		$this->assertSame( RevocationList::APPLY_ROLLBACK, $list->apply( $this->manifest( 2, array(), array( self::KEY_A ) ) ) );
		$this->assertSame( $before, get_option( RevocationList::OPTION_REVOCATIONS ) );
	}

	public function testExplicitUnrevokeRestoresAKey(): void {
		$list = new RevocationList();
		$list->apply( $this->manifest( 1, array( self::KEY_A, self::KEY_B ) ) );
		$list->apply( $this->manifest( 2, array(), array( self::KEY_A ) ) );

		$this->assertFalse( $list->isRevoked( self::KEY_A ) );
		$this->assertTrue( $list->isRevoked( self::KEY_B ) );
	}

	public function testAllDigitKeyIdSurvivesUnionAndPersistence(): void {
		// "1234567890123456" is valid hex but PHP coerces it to an INTEGER
		// array key. array_merge() would renumber it away and a strict
		// is_string() read-back check would drop it — both silently fail
		// open for exactly that key. Regression for both halves.
		$digit_key = '1234567890123456';

		$list = new RevocationList();
		$list->apply( $this->manifest( 1, array( $digit_key ) ) );

		// Survives a later union merge…
		$list->apply( $this->manifest( 2, array( self::KEY_A ) ) );
		$this->assertTrue( $list->isRevoked( $digit_key ) );
		$this->assertTrue( $list->isRevoked( self::KEY_A ) );

		// …and a fresh read from the persisted option.
		$this->assertTrue( ( new RevocationList() )->isRevoked( $digit_key ) );
	}

	public function testScalarOptionCorruptionDegradesToEmpty(): void {
		update_option( RevocationList::OPTION_REVOCATIONS, 'corrupted' );

		$list = new RevocationList();

		$this->assertFalse( $list->isRevoked( self::KEY_A ) );
		$this->assertSame( 0, $list->sequence() );

		// And a fresh apply starts over cleanly rather than fataling.
		$this->assertSame( RevocationList::APPLY_ACCEPTED, $list->apply( $this->manifest( 1, array( self::KEY_A ) ) ) );
		$this->assertTrue( $list->isRevoked( self::KEY_A ) );
	}

	public function testMalformedStoredEntriesAreIgnored(): void {
		// The option is scope-keyed; the default-scoped list reads the
		// 'default' bucket. Malformed innards of that bucket degrade rather
		// than fatal.
		update_option(
			RevocationList::OPTION_REVOCATIONS,
			array(
				'default' => array(
					'sequence' => '9', // Non-int: ignored, ratchet resets to 0.
					'revoked'  => array(
						self::KEY_A     => array( 'reason' => 'kept' ),
						'not-a-key-id'  => array( 'reason' => 'dropped' ),
						42              => array( 'reason' => 'dropped' ),
					),
				),
			)
		);

		$list = new RevocationList();

		$this->assertTrue( $list->isRevoked( self::KEY_A ) );
		$this->assertSame( array( self::KEY_A ), array_keys( $list->revokedKeys() ) );
		$this->assertSame( 0, $list->sequence() );
	}

	public function testLegacyFlatOptionShapeIsIgnored(): void {
		// A pre-scoping flat option (top-level sequence/revoked, no scope
		// layer) must NOT be read into any scope — migrating it would bleed
		// one root's revocations into every root, the exact thing scoping
		// prevents. Nothing shipped with the flat shape, so ignoring is safe.
		update_option(
			RevocationList::OPTION_REVOCATIONS,
			array(
				'sequence' => 5,
				'revoked'  => array( self::KEY_A => array( 'reason' => 'legacy' ) ),
			)
		);

		$this->assertFalse( ( new RevocationList() )->isRevoked( self::KEY_A ), 'Default scope must not read the flat shape.' );
		$this->assertFalse( ( new RevocationList( 'ROOT_A' ) )->isRevoked( self::KEY_A ), 'A root scope must not read the flat shape.' );
		$this->assertSame( 0, ( new RevocationList() )->sequence() );
	}

	public function testDifferentScopesAreIsolated(): void {
		// The cross-vendor isolation guarantee at the list level: a revocation
		// applied under one root scope is invisible to a list scoped to a
		// different root, and neither clobbers the other's bucket.
		$rootA = new RevocationList( 'ROOT_A' );
		$rootB = new RevocationList( 'ROOT_B' );

		$rootA->apply( $this->manifest( 1, array( self::KEY_A ) ) );

		$this->assertTrue( $rootA->isRevoked( self::KEY_A ) );
		$this->assertFalse( $rootB->isRevoked( self::KEY_A ), 'A different root must not see root A\'s revocation.' );

		// Root B revokes something of its own; root A is unaffected.
		$rootB->apply( $this->manifest( 1, array( self::KEY_B ) ) );

		$this->assertTrue( $rootB->isRevoked( self::KEY_B ) );
		$this->assertFalse( $rootA->isRevoked( self::KEY_B ) );
		$this->assertTrue( $rootA->isRevoked( self::KEY_A ), 'Root B\'s write must not have clobbered root A\'s bucket.' );
	}
}
