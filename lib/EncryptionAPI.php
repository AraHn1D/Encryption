<?php
	namespace encryption;

	interface EncryptionAPI {
		/**
		 * Method constructs the class
		 *
		 * EncryptionAPI constructor.
		 */
		public function __construct();

		/**
		 * Method encrypts the data
		 *
		 * @param $data
		 *
		 * @return mixed
		 */
		public function encrypt( $data );

		/**
		 * Method decrypts the data
		 *
		 * @param $data
		 *
		 * @return mixed
		 */
		public function decrypt( $data );
	}