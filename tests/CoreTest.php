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
				Encryption::_( [
					'mode' => Encryption::SERVER_MODE,
				] );

				$encrypted = Encryption::_()->encrypt( 'Test' );
				$decrypted = Encryption::_()->decrypt( $encrypted );
			}
			catch ( EncryptionError $error ) {
				return false;
			}

			return $decrypted instanceof Decrypted && $decrypted->getData() === 'Test';
		}
	}