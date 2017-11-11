<?php

namespace Salaros\WordPress;

use SecurityLib\Strength;
use RandomLib\Factory;

class Salts_Generator
{
	const ALL_CHARACTERS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_ []{}<>~`+=,.;:/?|!@#$%^&*()';

	/**
	* Salts that need to be generated
	*
	* @var array
	*/
	const DEFAULT_SALT_SPECS = [
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

	public static function writeToFile( $fileName, $content, $fileFlags = 0 )
	{
		$fileFlags = $fileFlags ?: ( file_exists( $fileName ) ) ? FILE_APPEND : 0;

		try {
			return file_put_contents( $fileName, $content, $fileFlags );
		} catch ( \Exception $ex ) {
			return false;
		}
	}

	public static function formatSalts( $salts, $outputFormat )
	{
		$lineTemplate = false;
		$lineEnd = PHP_EOL;
		$nameTransformFunc = 'strtoupper';

		switch ( $outputFormat ) {
			case 'env':
				$lineTemplate = "%s='%s'";
				$lineEnd = "\n";
				break;

			case 'yaml':
				$nameTransformFunc = 'strtolower';
				$lineTemplate = '%s: "%s"';
				break;

			case 'php':
			default:
				$lineTemplate = "define( '%s', '%s' );";
				break;
		}

		$formatted = array_map(function ( $name, $salt ) use ( $lineTemplate, $nameTransformFunc ) {
			$name = call_user_func( $nameTransformFunc, $name );
			return sprintf( $lineTemplate, $name, $salt );
		}, array_keys( $salts ), $salts );
		$formatted = implode( $lineEnd, $formatted );
		$formatted = $lineEnd . $formatted . $lineEnd;

		return $formatted;
	}

	public static function generateSalts( array $saltSpecs = null )
	{
		$saltSpecs = $saltSpecs ?: [];
		$saltSpecs = ( ! is_assoc_array( $saltSpecs ) )
			? array_fill_keys( $saltSpecs, '0' )
			: $saltSpecs;
		$saltSpecs = array_merge( self::DEFAULT_SALT_SPECS, $saltSpecs );

		$factory = new Factory();
		$generator = $factory->getGenerator( new Strength( Strength::MEDIUM ) );
		$salts = [];
		array_map( function ( $key, $length ) use ( &$salts, $generator ) {
			$length = intval( $length ) ?: 64;
			$salts[ $key ] = $generator->generateString( $length, self::ALL_CHARACTERS );
		}, array_keys( $saltSpecs ), $saltSpecs );
		return $salts;
	}
}

if (!function_exists('is_assoc_array')) {

	/**
	 * Checks if an array is associative or not
	 * @param  string  Array to test
	 * @return boolean Returns true in a given array is associative and false if it's not
	 */
	function is_assoc_array(array $array)
	{
		if (empty($array) || !is_array($array)) {
			return false;
		}

		foreach (array_keys($array) as $key) {
			if (!is_int($key)) {
				return true;
			}
		}
		return false;
	}
}
