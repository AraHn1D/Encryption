<?php

	namespace encryption;

	final class Decrypted {
		private $data;
		private $writable = true;

		const MESSAGES = [
			'closed' => 'Rejected! Instance can\'t be changed after it was closed.',
		];

		/**
		 * Method returns new instance of this class
		 *
		 * @return Decrypted
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
		 * Method fetches data from the class instance
		 *
		 * @return null|array
		 */
		public function getData() {
			return $this->data;
		}

		/**
		 * Method sets the data value by key
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