<?php
	require __DIR__ . '/../vendor/autoload.php';

	class CoreTest extends PHPUnit_Framework_TestCase {
		public function testCore() {
			try {
				\encryption\Encryption::_();
			}
			catch ( \encryption\EncryptionError $error ) {
				return 2;
			}
		}
	}