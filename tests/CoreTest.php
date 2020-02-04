<?php
	require __DIR__ . '/../vendor/autoload.php';

	class CoreTest extends PHPUnit_Framework_TestCase {
		public function testCore() {
			try {
				if ( \encryption\Encryption::_() instanceof \encryption\Encryption ) {
					return true;
				}
			}
			catch ( \encryption\EncryptionError $error ) {
				return false;
			}
		}
	}