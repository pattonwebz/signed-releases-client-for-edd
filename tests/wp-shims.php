<?php
/**
 * Minimal WordPress shims so UpdaterGuard can be unit tested without a
 * WordPress install. Only what the exercised code paths touch.
 */

declare(strict_types=1);

if ( ! class_exists( 'WP_Error' ) ) {
	class WP_Error {
		private string $c;
		private string $m;

		public function __construct( string $code = '', string $message = '' ) {
			$this->c = $code;
			$this->m = $message;
		}

		public function get_error_code(): string {
			return $this->c;
		}

		public function get_error_message(): string {
			return $this->m;
		}
	}
}

if ( ! function_exists( 'apply_filters' ) ) {
	function apply_filters( $tag, $value, ...$args ) {
		$override = $GLOBALS['__wp_filter_overrides'][ $tag ] ?? null;

		return null !== $override ? $override : $value;
	}
}

if ( ! function_exists( 'do_action' ) ) {
	function do_action( $tag, ...$args ) {
		$GLOBALS['__wp_actions'][] = array( 'tag' => $tag, 'args' => $args );
	}
}

if ( ! function_exists( 'get_option' ) ) {
	function get_option( $name, $default = false ) {
		return $GLOBALS['__wp_options'][ $name ] ?? $default;
	}
}

if ( ! function_exists( 'update_option' ) ) {
	function update_option( $name, $value, $autoload = null ) {
		$GLOBALS['__wp_options'][ $name ] = $value;

		return true;
	}
}

if ( ! function_exists( 'current_user_can' ) ) {
	function current_user_can( $cap ) {
		return $GLOBALS['__wp_user_can'] ?? true;
	}
}

if ( ! function_exists( 'esc_html' ) ) {
	function esc_html( $text ) {
		return htmlspecialchars( (string) $text, ENT_QUOTES );
	}
}

if ( ! function_exists( 'add_filter' ) ) {
	function add_filter( $tag, $callback, $priority = 10, $accepted_args = 1 ) {
		$GLOBALS['__wp_hooks'][] = array( 'tag' => $tag, 'callback' => $callback );

		return true;
	}
}

if ( ! function_exists( 'add_action' ) ) {
	function add_action( $tag, $callback, $priority = 10, $accepted_args = 1 ) {
		return add_filter( $tag, $callback, $priority, $accepted_args );
	}
}

function wp_shims_reset(): void {
	$GLOBALS['__wp_actions']          = array();
	$GLOBALS['__wp_options']          = array();
	$GLOBALS['__wp_hooks']            = array();
	$GLOBALS['__wp_filter_overrides'] = array();
	$GLOBALS['__wp_user_can']         = true;
}
