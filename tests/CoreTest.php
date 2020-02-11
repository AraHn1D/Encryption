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
				$instance = Encryption::_([
					'mode' => Encryption::SERVER_MODE
				]);
			}
			catch (EncryptionError $error) {
				return false;
			}

			return $instance instanceof \encryption\Encryption;
		}
	}