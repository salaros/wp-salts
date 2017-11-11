<?php

namespace Salaros\WordPress;

use SecurityLib\Strength;
use RandomLib\Factory;

class Salts_Generator {
	const ALL_CHARACTERS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_ []{}<>~`+=,.;:/?|!@#$%^&*()';

	/**
	* Salts that need to be generated
	*
	* @var array
	*/
	const SALT_SPECS = [
		'AUTH_KEY'          => 64,
		'SECURE_AUTH_KEY'   => 64,
		'LOGGED_IN_KEY'     => 64,
		'NONCE_KEY'         => 64,
		'AUTH_SALT'         => 64,
		'SECURE_AUTH_SALT'  => 64,
		'LOGGED_IN_SALT'    => 64,
		'NONCE_SALT'        => 64,
		'WP_CACHE_KEY_SALT' => 32,
	];

	public static function write_to_file( $file_name, $content, $file_flags = 0 ) {
		$file_flags = $file_flags ?: ( file_exists( $file_name ) ) ? FILE_APPEND : 0;

		try {
			return file_put_contents( $file_name, $content, $file_flags );
		} catch ( \Exception $ex ) {
			return false;
		}
	}

	public static function format_data( $data, $format ) {
		$template = false;
		$line_end = PHP_EOL;
		$call_func = 'strtoupper';

		switch ( $format ) {
			case 'env':
				$template = "%s='%s'";
				$line_end = "\n";
				break;

			case 'yaml':
				$call_func = 'strtolower';
				$template = '%s: "%s"';
				break;

			case 'php':
			default:
				$template = "define( '%s', '%s' );";
				break;
		}

		$formatted = array_map(function ( $name, $salt ) use ( $template, $call_func ) {
			$name = call_user_func( $call_func, $name );
			return sprintf( $template, $name, $salt );
		}, array_keys( $data ), $data );
		$formatted = implode( $line_end, $formatted );
		$formatted = $line_end . $formatted . $line_end;

		return $formatted;
	}

	public static function generate_salts() {
		$factory = new Factory();
		$generator = $factory->getGenerator( new Strength( Strength::MEDIUM ) );
		$salts = [];
		array_map( function ( $key, $length ) use ( &$salts, $generator ) {
			$salts[ $key ] = $generator->generateString( $length, self::ALL_CHARACTERS );
		}, array_keys( self::SALT_SPECS ), self::SALT_SPECS );
		return $salts;
	}
}
