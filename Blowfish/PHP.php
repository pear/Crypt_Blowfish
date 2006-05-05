<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Crypt_Blowfish allows for encryption and decryption on the fly using
 * the Blowfish algorithm. Crypt_Blowfish does not require the mcrypt
 * PHP extension, but uses it if available, otherwise it uses only PHP.
 * Crypt_Blowfish support encryption/decryption with or without a secret key.
 *
 * PHP versions 4 and 5
 *
 * LICENSE: This source file is subject to version 3.0 of the PHP license
 * that is available through the world-wide-web at the following URI:
 * http://www.php.net/license/3_0.txt.  If you did not receive a copy of
 * the PHP License and are unable to obtain it through the web, please
 * send a note to license@php.net so we can mail you a copy immediately.
 *
 * @category   Encryption
 * @package    Crypt_Blowfish
 * @author     Matthew Fonda <mfonda@php.net>
 * @author     Philippe Jausions <jausions@php.net>
 * @copyright  2005-2006 Matthew Fonda
 * @license    http://www.php.net/license/3_0.txt  PHP License 3.0
 * @version    CVS: $Id$
 * @link       http://pear.php.net/package/Crypt_Blowfish
 */

/**
 * Include base class
 */
require_once 'Crypt/Blowfish.php';

/**
 * Detect problem with XOR on some operating systems
 */
if (((-1 * 0xffffffff) ^ 0x7fffffff) < 0) {
    define('CRYPT_BLOWFISH_PHP_XORWORKAROUND', true);
} else {
    define('CRYPT_BLOWFISH_PHP_XORWORKAROUND', false);
}

/**
 * Common class for PHP-only implementations
 *
 * @category   Encryption
 * @package    Crypt_Blowfish
 * @author     Matthew Fonda <mfonda@php.net>
 * @author     Philippe Jausions <jausions@php.net>
 * @copyright  2005-2006 Matthew Fonda
 * @license    http://www.php.net/license/3_0.txt  PHP License 3.0
 * @link       http://pear.php.net/package/Crypt_Blowfish
 * @version    @package_version@
 * @access     public
 */
class Crypt_Blowfish_PHP extends Crypt_Blowfish
{
    /**
     * P-Array contains 18 32-bit subkeys
     *
     * @var array
     * @access protected
     */
    var $_P = array();

    /**
     * Array of four S-Blocks each containing 256 32-bit entries
     *
     * @var array
     * @access protected
     */
    var $_S = array();

    /**
     * Whether the IV is required
     *
     * @var boolean
     * @access protected
     */
    var $_iv_required = false;

    /**
     * Crypt_Blowfish_PHP Constructor
     * Initializes the Crypt_Blowfish object, and sets
     * the secret key
     *
     * @param string $key
     * @param string $mode operating mode 'ecb' or 'cbc'
     * @param string $iv initialization vector
     * @access protected
     */
    function __construct($key = null, $iv = null)
    {
        $this->_iv = $iv . ((strlen($iv) < 8)
                            ? str_repeat(chr(0), 8 - strlen($iv)) : '');
        if (!is_null($key)) {
            $this->setKey($key, $this->_iv);
        }
    }

    /**
     * Initializes the Crypt_Blowfish object
     *
     * @access private
     */
    function _init()
    {
        require_once 'Crypt/Blowfish/DefaultKey.php';
        $defaults = new Crypt_Blowfish_DefaultKey();
        $this->_P = $defaults->P;
        $this->_S = $defaults->S;
    }

    /**
     * Workaround for XOR on certain systems
     *
     * @param integer|float $l
     * @param integer|float $r
     * @return float
     * @access protected
     */
    function _binxor($l, $r)
    {
        $x = (($l < 0) ? (float)($l + 4294967296) : (float)$l)
             ^ (($r < 0) ? (float)($r + 4294967296) : (float)$r);

        return (float)(($x < 0) ? $x + 4294967296 : $x);
    }

    /**
     * Unpack 2 32-bit integers, keeping them positive
     *
     * @param string $data
     * @return array
     * @access protected
     */
    function _unpackN2($data)
    {
        list(, $N1, $N2) = unpack('N2', $data);
        //return array($N1, $N2);

        return array(
            (float)(($N1 < 0) ? $N1 + 4294967296 : $N1),
            (float)(($N2 < 0) ? $N2 + 4294967296 : (float)$N2));
    }

    /**
     * Enciphers a single 64-bit block
     *
     * @param int &$Xl
     * @param int &$Xr
     * @access protected
     */
    function _encipher(&$Xl, &$Xr)
    {
        for ($i = 0; $i < 16; $i++) {
            $temp = $Xl ^ $this->_P[$i];
            $Xl = ((($this->_S[0][($temp >> 24) & 255]
                     + $this->_S[1][($temp >> 16) & 255]
                    ) ^ $this->_S[2][($temp >> 8) & 255]
                   ) + $this->_S[3][$temp & 255]
                  ) ^ $Xr;
            $Xr = $temp;
        }
        $Xr = $Xl ^ $this->_P[16];
        $Xl = $temp ^ $this->_P[17];
    }

    /**
     * Deciphers a single 64-bit block
     *
     * @param int &$Xl
     * @param int &$Xr
     * @access protected
     */
    function _decipher(&$Xl, &$Xr)
    {
        for ($i = 17; $i > 1; $i--) {
            $temp = $Xl ^ $this->_P[$i];
            $Xl = ((($this->_S[0][($temp >> 24) & 255]
                     + $this->_S[1][($temp >> 16) & 255]
                    ) ^ $this->_S[2][($temp >> 8) & 255]
                   ) + $this->_S[3][$temp & 255]
                  ) ^ $Xr;
            $Xr = $temp;
        }
        $Xr = $Xl ^ $this->_P[1];
        $Xl = $temp ^ $this->_P[0];
    }

    /**
     * Enciphers a single 64-bit block
     *
     * Enciphers using the internal _binxor() method
     *
     * @param int &$Xl
     * @param int &$Xr
     * @access protected
     */
    function _encipher2(&$Xl, &$Xr)
    {
        if ($Xl < 0) {
            $Xl += 4294967296;
        }
        if ($Xr < 0) {
            $Xr += 4294967296;
        }

        for ($i = 0; $i < 16; $i++) {
            $temp = $Xl ^ $this->_P[$i];
            if ($temp < 0) {
                $temp += 4294967296;
            }

            $Xl = ((($this->_S[0][($temp >> 24) & 255]
                     + $this->_S[1][($temp >> 16) & 255]
                    ) ^ $this->_S[2][($temp >> 8) & 255]
                   ) + $this->_S[3][$temp & 255]
                  ) ^ $Xr;
/*            $Xl = $this->_binxor(
                    $this->_binxor($this->_S[0][($temp >> 24) & 255]
                                     + $this->_S[1][($temp >> 16) & 255]
                                   , $this->_S[2][($temp >> 8) & 255]
                   ) + $this->_S[3][$temp & 255], $Xr); */
            $Xr = $temp;
        }
        $Xr = $this->_binxor($Xl, $this->_P[16]);
        $Xl = $this->_binxor($temp, $this->_P[17]);
    }

    /**
     * Deciphers a single 64-bit block
     *
     * Deciphers using the internal _binxor() method
     *
     * @param int &$Xl
     * @param int &$Xr
     * @access protected
     */
    function _decipher2(&$Xl, &$Xr)
    {
        if ($Xl < 0) {
            $Xl += 4294967296;
        }
        if ($Xr < 0) {
            $Xr += 4294967296;
        }

        for ($i = 17; $i > 1; $i--) {
            $temp = $Xl ^ $this->_P[$i];
            if ($temp < 0) {
                $temp += 4294967296;
            }

            $Xl = ((($this->_S[0][($temp >> 24) & 255]
                     + $this->_S[1][($temp >> 16) & 255]
                    ) ^ $this->_S[2][($temp >> 8) & 255]
                   ) + $this->_S[3][$temp & 255]
                  ) ^ $Xr;
/*            $Xl = $this->_binxor(
                    $this->_binxor($this->_S[0][($temp >> 24) & 255]
                                    + $this->_S[1][($temp >> 16) & 255]
                                   , $this->_S[2][($temp >> 8) & 255]
                   ) + $this->_S[3][$temp & 255], $Xr); */
            $Xr = $temp;
        }
        $Xr = $this->_binxor($Xl, $this->_P[1]);
        $Xl = $this->_binxor($temp, $this->_P[0]);
    }

    /**
     * Sets the secret key
     * The key must be non-zero, and less than or equal to
     * 56 characters (bytes) in length.
     *
     * If you are making use of the PHP mcrypt extension, you must call this
     * method before each encrypt() and decrypt() call.
     *
     * @param string $key
     * @param string $iv 8-char initialization vector (required for CBC mode)
     * @return boolean|PEAR_Error  Returns TRUE on success, PEAR_Error on failure
     * @access public
     */
    function setKey($key, $iv = null)
    {
        static $keyHash = null;

        if (!is_string($key)) {
            return PEAR::raiseError('Key must be a string', 2);
        }

        $len = strlen($key);

        if ($len > 56 || $len == 0) {
            return PEAR::raiseError('Key must be less than 56 characters (bytes) and non-zero. Supplied key length: ' . $len, 3);
        }

        if ($this->_iv_required) {
            if (strlen($iv) != 8) {
                return PEAR::raiseError('IV must be 8-character (byte) long. Supplied IV length: ' . strlen($iv), 7);
            }
            $this->_iv = $iv;
        }

        // If same key passed, no need to re-initialize internal arrays.
        // @todo This needs to be worked out better...
        if ($keyHash == md5($key)) {
            return true;
        }

        $funcName = (CRYPT_BLOWFISH_PHP_XORWORKAROUND)
                    ? '_encipher2' : '_encipher2';

        $this->_init();

        $k = 0;
        $data = 0;
        $datal = 0;
        $datar = 0;

        for ($i = 0; $i < 18; $i++) {
            $data = 0;
            for ($j = 4; $j > 0; $j--) {
                    $data = $data << 8 | ord($key{$k});
                    $k = ($k+1) % $len;
            }
            $this->_P[$i] ^= $data;
        }

        for ($i = 0; $i <= 16; $i += 2) {
            $this->{$funcName}($datal, $datar);
            $this->_P[$i] = $datal;
            $this->_P[$i+1] = $datar;
        }
        for ($i = 0; $i < 256; $i += 2) {
            $this->{$funcName}($datal, $datar);
            $this->_S[0][$i] = $datal;
            $this->_S[0][$i+1] = $datar;
        }
        for ($i = 0; $i < 256; $i += 2) {
            $this->{$funcName}($datal, $datar);
            $this->_S[1][$i] = $datal;
            $this->_S[1][$i+1] = $datar;
        }
        for ($i = 0; $i < 256; $i += 2) {
            $this->{$funcName}($datal, $datar);
            $this->_S[2][$i] = $datal;
            $this->_S[2][$i+1] = $datar;
        }
        for ($i = 0; $i < 256; $i += 2) {
            $this->{$funcName}($datal, $datar);
            $this->_S[3][$i] = $datal;
            $this->_S[3][$i+1] = $datar;
        }

        $keyHash = md5($key);
        return true;
    }
}

?>