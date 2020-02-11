<?php
	require __DIR__ . '/../vendor/autoload.php';

	use PHPUnit\Framework\TestCase;
	use encryption\Encryption;
	use encryption\Encrypted;
	use encryption\Decrypted;
	use encryption\EncryptionError;

	class CoreTest extends TestCase {
		public function testCore() {
			try {
				return Encryption::_() instanceof Encryption;
			}
			catch ( EncryptionError $error ) {
				return false;
			}
		}
	}