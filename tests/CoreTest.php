<?php
	require __DIR__ . '/../vendor/autoload.php';

	use PHPUnit\Framework\TestCase;

	class CoreTest extends TestCase {
		public function testCore() {
			var_dump( php_sapi_name() );

			return \encryption\Encryption::_() instanceof \encryption\Encryption;
		}
	}