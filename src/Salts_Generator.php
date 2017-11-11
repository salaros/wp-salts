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

	public static function writeToFile( $fileName, $content, $fileFlags = 0 )
	{
		$fileFlags = $fileFlags ?: ( file_exists( $fileName ) ) ? FILE_APPEND : 0;

		try {
			return file_put_contents( $fileName, $content, $fileFlags );
		} catch ( \Exception $ex ) {
			return false;
		}
	}

	public static function formatSalts( $salts, $outputFormat)
	{
		$lineTemplate = false;
		$lineEnd = PHP_EOL;
		$nameTransformFunc = 'strtoupper';

		switch ( $outputFormat) {
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

	public static function generateSalts()
	{
		$factory = new Factory();
		$generator = $factory->getGenerator( new Strength( Strength::MEDIUM ) );
		$salts = [];
		array_map( function ( $key, $length ) use ( &$salts, $generator ) {
			$salts[ $key ] = $generator->generateString( $length, self::ALL_CHARACTERS );
		}, array_keys( self::SALT_SPECS ), self::SALT_SPECS );
		return $salts;
	}
}
