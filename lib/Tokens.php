<?php

	namespace encryption;

	final class Tokens {
		private $public;
		private $client;
		private $server;
		private $writable = true;

		/**
		 * @var $props_allowed_amount int
		 * Here 6 - because this method returns 3 properties (encrypted data, key and vector)
		 * It allows to developer determine how these properties will be represented at output
		 * false - at binary representation, true - hexadecimal
		 */
		private static $props_allowed_amount = 6;

		/**
		 * Throwable messages
		 */
		const MESSAGES = [
			'return' => 'Rejected! Info can\'t be returned before instance was closed.',
			'closed' => 'Rejected! Instance can\'t be changed after it was closed.',
		];

		/**
		 * Method returns new instance of this class
		 *
		 * @return Tokens
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
		 * Method encode the tokens into json for external use
		 *
		 * @param string|array|null $qualifier
		 * @param string|null       $key
		 *
		 * @return string
		 * @throws EncryptionError
		 */
		public function json( $qualifier = null, $key = null ) {
			return json_encode( $this->get( $qualifier, $key, false ) );
		}

		/**
		 * Method serializes the tokens for external use
		 *
		 * @param string|array|null $qualifier
		 * @param string|null       $key
		 *
		 * @return string
		 * @throws EncryptionError
		 */
		public function serialize( $qualifier = null, $key = null ) {
			return serialize( $this->get( $qualifier, $key, false ) );
		}

		/**
		 * Method gets the token using qualifier or/and key
		 *
		 * @param string|array|null $qualifier
		 * @param string|null       $key
		 * @param bool|array        $binary
		 *
		 * @return mixed
		 * @throws EncryptionError
		 */
		public function get( $qualifier = null, $key = null, $binary = false ) {
			$binary = isset( $binary ) ? ( is_array( $binary ) || is_bool( $binary ) ? $binary : false ) : ( is_bool( $binary ) ? $binary : false );

			if ( is_array( $binary ) ) {
				array_splice( $binary, self::$props_allowed_amount );

				for ( $index = 0; $index < self::$props_allowed_amount; $index++ ) {
					if ( !isset( $binary[ $index ] ) || !is_bool( $binary[ $index ] ) ) {
						$binary[ $index ] = false;
					}
				}
			}

			if ( !$this->writable ) {
				if ( !$qualifier || is_array( $qualifier ) ) {
					$return = [];

					$return[ 'public' ][ 'key' ]    = is_array( $binary ) ? ( $binary[ 0 ] ? $this->public[ 'key' ] : bin2hex( $this->public[ 'key' ] ) ) : ( $binary ? $this->public[ 'key' ] : bin2hex( $this->public[ 'key' ] ) );
					$return[ 'public' ][ 'vector' ] = is_array( $binary ) ? ( $binary[ 1 ] ? $this->public[ 'vector' ] : bin2hex( $this->public[ 'vector' ] ) ) : ( $binary ? $this->public[ 'vector' ] : bin2hex( $this->public[ 'vector' ] ) );

					$return[ 'client' ][ 'key' ]    = is_array( $binary ) ? ( $binary[ 2 ] ? $this->client[ 'key' ] : bin2hex( $this->client[ 'key' ] ) ) : ( $binary ? $this->client[ 'key' ] : bin2hex( $this->client[ 'key' ] ) );
					$return[ 'client' ][ 'vector' ] = is_array( $binary ) ? ( $binary[ 3 ] ? $this->client[ 'vector' ] : bin2hex( $this->client[ 'vector' ] ) ) : ( $binary ? $this->client[ 'vector' ] : bin2hex( $this->client[ 'vector' ] ) );
					$return[ 'client' ][ 'state' ]  = $this->client[ 'state' ];

					$return[ 'server' ][ 'key' ]    = is_array( $binary ) ? ( $binary[ 4 ] ? $this->server[ 'key' ] : bin2hex( $this->server[ 'key' ] ) ) : ( $binary ? $this->server[ 'key' ] : bin2hex( $this->server[ 'key' ] ) );
					$return[ 'server' ][ 'vector' ] = is_array( $binary ) ? ( $binary[ 5 ] ? $this->server[ 'vector' ] : bin2hex( $this->server[ 'vector' ] ) ) : ( $binary ? $this->server[ 'vector' ] : bin2hex( $this->server[ 'vector' ] ) );

					if ( is_array( $qualifier ) ) {
						$return_with_qualifiers = [];

						foreach ( $qualifier as $item ) {
							if ( !empty( $return[ $item ] ) ) {
								$return_with_qualifiers[ $item ] = $return[ $item ];
							}
						}

						return $return_with_qualifiers;
					}

					return $return;
				}
				else if ( !!$qualifier && !$key ) {
					$return = [];

					$return[ $qualifier ][ 'key' ]    = is_array( $binary ) ? ( $binary[ 0 ] ? $this->$qualifier[ 'key' ] : bin2hex( $this->$qualifier[ 'key' ] ) ) : ( $binary ? $this->$qualifier[ 'key' ] : bin2hex( $this->$qualifier[ 'key' ] ) );
					$return[ $qualifier ][ 'vector' ] = is_array( $binary ) ? ( $binary[ 1 ] ? $this->$qualifier[ 'vector' ] : bin2hex( $this->$qualifier[ 'vector' ] ) ) : ( $binary ? $this->$qualifier[ 'vector' ] : bin2hex( $this->$qualifier[ 'vector' ] ) );

					if ( isset( $this->$qualifier[ 'state' ] ) ) {
						$return[ $qualifier ][ 'state' ] = $this->$qualifier[ 'state' ];
					}

					return $return;
				}
				else {
					return is_array( $binary ) ? ( $binary[ 0 ] ? $this->$qualifier[ $key ] : bin2hex( $this->$qualifier[ $key ] ) ) : ( $binary ? $this->$qualifier[ $key ] : bin2hex( $this->$qualifier[ $key ] ) );
				}
			}
			else {
				throw new EncryptionError( self::MESSAGES[ 'return' ] );
			}
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