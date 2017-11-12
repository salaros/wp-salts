<?php

namespace Salaros\WordPress;

use SecurityLib\Strength;
use RandomLib\Factory;

class SaltsGenerator
{
    const ALL_CHARACTERS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_ []{}<>~`+=,.;:/?|!@#$%^&*()';

    /**
    * Salts that need to be generated
    *
    * @var array
    */
    const DEFAULT_SALT_SPECS = [
        'AUTH_KEY',
        'SECURE_AUTH_KEY',
        'LOGGED_IN_KEY',
        'NONCE_KEY',
        'AUTH_SALT',
        'SECURE_AUTH_SALT',
        'LOGGED_IN_SALT',
        'NONCE_SALT',
    ];

    public static function writeToFile($outputFormat, $fileName, array $additionalSalts = null, $fileFlags = 0)
    {
        $outputFormat = $outputFormat ?: self::guessFileFormat($fileName);
        $formatted = self::generateFormattedSalts($outputFormat, $additionalSalts);
        $fileFlags = $fileFlags ?: (file_exists($fileName)) ? FILE_APPEND : 0;
        try {
            return file_put_contents($fileName, $formatted, $fileFlags);
        } catch (\Exception $ex) {
            return false;
        }
    }

    public static function formatSalts($outputFormat, array $salts)
    {
        if (! is_assoc_array($salts)) {
            throw new \InvalidArgumentException(
                "Salts must be an associative array, e.g [ 'MY_SALT' => '3D.c=X7W}CCKB^' ]"
            );
        }

        $lineTemplate = false;
        $lineEnd = PHP_EOL;
        $nameTransformFunc = 'strtoupper';

        switch ($outputFormat) {
            case 'env':
                $lineTemplate = "%s='%s'";
                $lineEnd = "\n";
                break;

            case 'yaml':
            case 'yml':
                $nameTransformFunc = 'strtolower';
                $lineTemplate = '%s: "%s"';
                break;

            case 'php':
            default:
                $lineTemplate = "define('%s', '%s');";
                break;
        }

        $formatted = array_map(function ($name, $salt) use ($lineTemplate, $nameTransformFunc) {
            $name = call_user_func($nameTransformFunc, $name);
            return sprintf($lineTemplate, $name, $salt);
        }, array_keys($salts), $salts);
        $formatted = implode($lineEnd, $formatted);
        $formatted = $lineEnd . $formatted . $lineEnd;

        return $formatted;
    }

    public static function generateSalts(array $additionalSalts = null)
    {
        $additionalSalts = $additionalSalts ?: [];
        $additionalSalts = (! is_assoc_array($additionalSalts))
            ? array_fill_keys($additionalSalts, '0')
            : $additionalSalts;
        $saltSpecs = array_merge(
            array_fill_keys(self::DEFAULT_SALT_SPECS, '64'),
            $additionalSalts
        );

        $factory = new Factory();
        $generator = $factory->getGenerator(new Strength(Strength::MEDIUM));
        $salts = [];
        foreach ($saltSpecs as $key => $saltLength) {
            if (empty($key)) {
                continue;
            }
            $saltLength = intval($saltLength) ?: 64;
            $salts[ $key ] = $generator->generateString($saltLength, self::ALL_CHARACTERS);
        }
        return $salts;
    }

    public static function generateFormattedSalts($outputFormat, array $additionalSalts = null)
    {
        $salts = self::generateSalts($additionalSalts);
        $formatted = self::formatSalts($outputFormat, $salts);
        return $formatted;
    }

    public static function guessFileFormat($fileName)
    {
        $fileInfo = pathinfo($fileName);
        $fileExtension = (isset($fileInfo['extension']))
            ? strtolower($fileInfo['extension'])
            : '';

        if (empty($fileExtension)) {
            return null;
        }

        if ("env" === substr($fileExtension, -strlen('env'))) {
            return 'env';
        } elseif (substr($fileExtension, -strlen('yml')) === 'yml') {
            return 'yaml';
        } elseif (substr($fileExtension, -strlen('php')) === 'php') {
            return 'php';
        } elseif (false !== strpos($fileName, '.env')) {
            return 'env';
        } elseif (false !== strpos($fileName, '.yml')) {
            return 'yaml';
        } elseif (false !== strpos($fileName, '.php')) {
            return 'php';
        }

        return null;
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
