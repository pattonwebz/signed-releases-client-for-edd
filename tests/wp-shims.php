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

if ( ! function_exists( '__' ) ) {
	function __( $text, $domain = 'default' ) {
		return $text;
	}
}

if ( ! function_exists( 'esc_html__' ) ) {
	function esc_html__( $text, $domain = 'default' ) {
		return esc_html( __( $text, $domain ) );
	}
}

if ( ! function_exists( 'add_filter' ) ) {
	function add_filter( $tag, $callback, $priority = 10, $accepted_args = 1 ) {
		$GLOBALS['__wp_hooks'][] = array(
			'tag'           => $tag,
			'callback'      => $callback,
			'priority'      => $priority,
			'accepted_args' => $accepted_args,
		);

		return true;
	}
}

if ( ! function_exists( 'add_action' ) ) {
	function add_action( $tag, $callback, $priority = 10, $accepted_args = 1 ) {
		return add_filter( $tag, $callback, $priority, $accepted_args );
	}
}

if ( ! function_exists( 'is_wp_error' ) ) {
	function is_wp_error( $thing ) {
		return $thing instanceof WP_Error;
	}
}

if ( ! function_exists( 'add_query_arg' ) ) {
	// Like the real one, values are appended verbatim — add_query_arg() does
	// NOT urlencode, which is exactly what defaultSignatureFetcher() must
	// compensate for.
	function add_query_arg( $args, $url ) {
		$pairs = array();

		foreach ( $args as $key => $value ) {
			$pairs[] = $key . '=' . $value;
		}

		return $url . ( false === strpos( $url, '?' ) ? '?' : '&' ) . implode( '&', $pairs );
	}
}

if ( ! function_exists( 'wp_safe_remote_get' ) ) {
	// Records every request; responses come from a FIFO queue. An empty queue
	// yields a WP_Error, like an unreachable host.
	function wp_safe_remote_get( $url, $args = array() ) {
		$GLOBALS['__wp_http_requests'][] = array( 'url' => $url, 'args' => $args );

		if ( ! empty( $GLOBALS['__wp_http_queue'] ) ) {
			return array_shift( $GLOBALS['__wp_http_queue'] );
		}

		return new WP_Error( 'http_request_failed', 'No response queued.' );
	}
}

if ( ! function_exists( 'wp_remote_retrieve_response_code' ) ) {
	function wp_remote_retrieve_response_code( $response ) {
		if ( is_wp_error( $response ) || ! isset( $response['response']['code'] ) ) {
			return '';
		}

		return $response['response']['code'];
	}
}

if ( ! function_exists( 'wp_remote_retrieve_body' ) ) {
	function wp_remote_retrieve_body( $response ) {
		if ( is_wp_error( $response ) || ! isset( $response['body'] ) ) {
			return '';
		}

		return $response['body'];
	}
}

if ( ! function_exists( 'get_site_transient' ) ) {
	function get_site_transient( $name ) {
		return $GLOBALS['__wp_site_transients'][ $name ] ?? false;
	}
}

function wp_shims_reset(): void {
	$GLOBALS['__wp_actions']          = array();
	$GLOBALS['__wp_options']          = array();
	$GLOBALS['__wp_hooks']            = array();
	$GLOBALS['__wp_filter_overrides'] = array();
	$GLOBALS['__wp_user_can']         = true;
	$GLOBALS['__wp_http_requests']    = array();
	$GLOBALS['__wp_http_queue']       = array();
	$GLOBALS['__wp_site_transients']  = array();
}
