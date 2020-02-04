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

		/**
		 * Method sets length for the key
		 *
		 * @param int $length
		 *
		 * @return mixed
		 */
		public function setLength( $length = 70 );

		/**
		 * Method gets the encryption key
		 *
		 * @return mixed
		 */
		public function getKey();

		/**
		 * Method gets the encryption vector
		 *
		 * @return mixed
		 */
		public function getVector();
	}