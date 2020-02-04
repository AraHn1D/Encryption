<?php

	namespace encryption;

	final class Encrypted {
		private $data;
		private $tokens;
		private $writable = true;

		const MESSAGES = [
			'closed'           => 'Rejected! Instance can\'t be changed after it was closed.',
			'incorrect_tokens' => 'Internal error! Tokens are incorrect.',
		];

		/**
		 * Method returns new instance of this class
		 *
		 * @return Encrypted
		 */
		public static function _() {
			return new self;
		}

		/**
		 * Method closing the possibility of writing info in class instance
		 *
		 * @return $this
		 */
		public function close() {
			$this->writable = false;

			return $this;
		}

		/**
		 * Method gets the token using qualifier or/and key
		 *
		 * @return Tokens
		 * @throws EncryptionError
		 */
		public function tokens() {
			if ( $this->tokens instanceof Tokens ) {
				return $this->tokens;
			}
			else {
				throw new EncryptionError( self::MESSAGES[ 'incorrect_tokens' ] );
			}
		}

		/**
		 * Method fetches data from the class instance
		 *
		 * @param bool $binary
		 *
		 * @return null|string
		 */
		public function getData( $binary = false ) {
			$binary = !!$binary;

			return $binary ? $this->data : bin2hex( $this->data );
		}

		/**
		 * Main setter, method sets variables using name and value parameters
		 *
		 * @param $name
		 * @param $value
		 *
		 * @return $this
		 * @throws EncryptionError
		 */
		public function set( $name, $value ) {
			if ( $this->writable ) {
				$this->$name = $value;

				return $this;
			}
			else {
				throw new EncryptionError( self::MESSAGES[ 'closed' ] );
			}
		}
	}