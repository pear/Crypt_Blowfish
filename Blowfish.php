<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Crypt_Blowfish allows for encryption and decryption on the fly using
 * the Blowfish algorithm. Crypt_Blowfish does not require the mcrypt
 * PHP extension, it uses only PHP.
 * Crypt_Blowfish support encryption/decryption with or without a secret key.
 *
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
 * @copyright  2005 Matthew Fonda
 * @license    http://www.php.net/license/3_0.txt  PHP License 3.0
 * @version    CVS: $Id$
 * @link       http://pear.php.net/package/Crypt_Blowfish
 */


require_once 'PEAR.php';
require_once 'Blowfish/DefaultKey.php';


/**
 *
 * Example usage:
 * $bf = new Crypt_Blowfish('some secret key!');
 * $encrypted = $bf->encrypt('this is some example plain text');
 * $plaintext = $bf->decrypt($encrypted);
 * echo "plain text: $plaintext";
 *
 *
 * @category   Encryption
 * @package    Crypt_Blowfish
 * @author     Matthew Fonda <mfonda@php.net>
 * @copyright  2005 Matthew Fonda
 * @license    http://www.php.net/license/3_0.txt  PHP License 3.0
 * @link       http://pear.php.net/package/Crypt_Blowfish
 * @version    @package_version@
 * @access     public
 */
class Crypt_Blowfish
{
    /**
     * P-Array contains 18 32-bit subkeys
     *
     * @var array
     * @access private
     */
    var $_P = array();
    
    
    /**
     * Array of four S-Blocks each containing 256 32-bit entries
     *
     * @var array
     * @access private
     */
    var $_S = array();

    
    /**
     * Crypt_Blowfish Constructor
     * Initializes the Crypt_Blowfish object, and gives a sets
     * the secret key if one is provided
     *
     * @param string $key
     * @access public
     */
    function Crypt_Blowfish($key = null)
    {
        $this->setKey($key);
    }
    
    /**
     * Deprecated isReady method
     *
     * @return bool
     * @access public
     * @deprecated
     */
    function isReady()
    {
        return true;
    }
    
    /**
     * Deprecated init method - init is now a private
     * method and has been replaced with _init
     *
     * @return bool
     * @access public
     * @deprecated
     * @see Crypt_Blowfish::_init()
     */
    function init()
    {
        $this->_init();
    }
    
    /**
     * Initializes the Crypt_Blowfish object
     *
     * @access private
     */
    function _init()
    {
        $defaults = new Crypt_Blowfish_DefaultKey();
        $this->_P = $defaults->P;
        $this->_S = $defaults->S;
    }
            
    /**
     * Enciphers a single 64 bit block
     *
     * @param int &$Xl
     * @param int &$Xr
     * @access private
     */
    function _encipher(&$Xl, &$Xr)
    {
        for ($i = 0; $i < 16; $i++) {
            $temp = $Xl ^ $this->_P[$i];
            $Xl = ((($this->_S[0][($temp>>24) & 255] +
                            $this->_S[1][($temp>>16) & 255]) ^
                            $this->_S[2][($temp>>8) & 255]) +
                            $this->_S[3][$temp & 255]) ^ $Xr;
            $Xr = $temp;
        }
        $Xr = $Xl ^ $this->_P[16];
        $Xl = $temp ^ $this->_P[16+1];
    }
    
    
    /**
     * Deciphers a single 64 bit block
     *
     * @param int &$Xl
     * @param int &$Xr
     * @access private
     */
    function _decipher(&$Xl, &$Xr)
    {
        for ($i = 16 + 1; $i > 1; $i--) {
            $temp = $Xl ^ $this->_P[$i];
            $Xl = ((($this->_S[0][ ($temp>>24) & 255 ] +
                            $this->_S[1][($temp>>16) & 255]) ^
                            $this->_S[2][($temp>>8) & 255]) +
                            $this->_S[3][$temp & 255]) ^ $Xr;
            $Xr = $temp;
        }
        $Xr = $Xl ^ $this->_P[1];
        $Xl = $temp ^ $this->_P[0];
    }
    
    
    /**
     * Encrypts a string
     *
     * @param string $plainText
     * @return string Returns cipher text on success, PEAR_Error on failure
     * @access public
     */
    function encrypt($plainText)
    {
        $plainText = (String)$plainText;
        $cipherText = '';
        $len = strlen($plainText);
        $plainText .= str_repeat(chr(0),(8 - ($len%8))%8);
        for ($i = 0; $i < $len; $i += 8) {
            list(,$Xl,$Xr) = unpack("N2",substr($plainText,$i,8));
            $this->_encipher($Xl, $Xr);
            $cipherText .= pack("N2", $Xl, $Xr);
        }
        return $cipherText;
    }
    
    
    /**
     * Decrypts an encrypted string
     *
     * @param string $cipherText
     * @return string Returns plain text on success, PEAR_Error on failure
     * @access public
     */
    function decrypt($cipherText)
    {
        $cipherText = (String)$cipherText;
        $plainText = '';
        $len = strlen($cipherText);
        $cipherText .= str_repeat(chr(0),(8 - ($len%8))%8);
        for ($i = 0; $i < $len; $i += 8) {
            list(,$Xl,$Xr) = unpack("N2",substr($cipherText,$i,8));
            $this->_decipher($Xl, $Xr);
            $plainText .= pack("N2", $Xl, $Xr);
        }
        return $plainText;
    }
    
    
    /**
     * Sets the secret key
     * The key must be greater than or equal to 4 characters
     * in length, and less than or equal to 56 characters in
     * length. It must also be divisible by four. If the optional
     * key parameter is not passed, it will set the key back to
     * the default key.
     *
     * @param string $key
     * @return bool  Returns true on success, PEAR_Error on failure
     * @access public
     */
    function setKey($key = null)
    {
        if (!isset($key)) {
            $this->_init();
            return true;
        }
        
        $key = (String)$key;
        $len = strlen($key);
        
        if ($len < 4 || $len > 56 || $len % 4) {
            return PEAR::raiseError('Invalid key provided. Keys must be between 4 and 56 characters long and divisible by 4', 1, PEAR_ERROR_DIE);
        }
        
        $this->_init();
        
        $k = 0;
        $data = 0;
        $datal = 0;
        $datar = 0;
        
        for ($i = 0; $i < 16 + 2; $i++) {
            $data = 0;
            for ($j = 4; $j > 0; $j--) {
                    $data = $data << 8 | ord($key{$k});
                    $k = ($k+1) % $len;
            }
            $this->_P[$i] ^= $data;
        }
        
        for ($i = 0; $i <= 16; $i += 2) {
            $this->_encipher($datal, $datar);
            $this->_P[$i] = $datal;
            $this->_P[$i+1] = $datar;
        }
        for ($i = 0; $i < 256; $i += 2) {
            $this->_encipher($datal, $datar);
            $this->_S[0][$i] = $datal;
            $this->_S[0][$i+1] = $datar;
        }
        for ($i = 0; $i < 256; $i += 2) {
            $this->_encipher($datal, $datar);
            $this->_S[1][$i] = $datal;
            $this->_S[1][$i+1] = $datar;
        }
        for ($i = 0; $i < 256; $i += 2) {
            $this->_encipher($datal, $datar);
            $this->_S[2][$i] = $datal;
            $this->_S[2][$i+1] = $datar;
        }
        for ($i = 0; $i < 256; $i += 2) {
            $this->_encipher($datal, $datar);
            $this->_S[3][$i] = $datal;
            $this->_S[3][$i+1] = $datar;
        }
        
        return true;
    }
    
}

?>
