<?php
	require __DIR__ . '/../vendor/autoload.php';

	use PHPUnit\Framework\TestCase;

	class CoreTest extends TestCase {
		public function testCore() {
			return \encryption\Encryption::_() instanceof \encryption\Encryption;
		}
	}