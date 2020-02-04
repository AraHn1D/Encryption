<?php
	/**
	 * This is Encryption API's loader file
	 * It isn't strongly recommended to modify this file if you don't understand what exactly happens here!
	 */

	namespace encryption;

	/* Encryption API interface */
	require_once 'EncryptionAPI.php';

	/* Encryption errors exception handler */
	require_once 'EncryptionError.php';

	/* Encryption result classes */
	require_once 'Encrypted.php';
	require_once 'Decrypted.php';
	require_once 'Tokens.php';

	/* Encryption class */
	require_once 'Encryption.php';