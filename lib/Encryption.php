<?php

	namespace encryption;

	/**
	 * Encryption class
	 * This class is going to destroy developers myths that "client" can't exchanging information secure with "server"
	 *
	 * @package  Encryption
	 * @author   Yury Marty
	 * @link     https://github.com/AraHn1D/Encryption
	 */
	class Encryption implements EncryptionAPI {
		/**
		 * Private properties for inner uses
		 */
		private $key    = null;
		private $vector = null;
		private $length = null;
		private $mode   = null;
		private $method = null;

		/**
		 * Static properties
		 */
		public static $version     = '1.3.0.6';
		public static $className   = null;
		public static $lcClassName = null;

		/**
		 * Static property which will be set to this class instance if class was initiated properly
		 * @var $instance null|Encryption
		 */
		private static $instance = null;

		/**
		 * Constant properties
		 */
		const CLIENT_MODE             = 0;
		const SERVER_MODE             = 1;
		const CLIENT_SERVER_MODE      = 2;
		const SERVER_TOKENS_FILE_PATH = __DIR__ . DIRECTORY_SEPARATOR . 'encryption.static';

		/**
		 * Constant messages
		 */
		const INTERNAL_ERROR           = 'Internal error!';
		const FAILED_TO_CONSTUCT_CLASS = 'Failed to construct and init class!';
		const PUBLIC_TOKENS_WERENT_SET = 'Public tokens weren\'t set';
		const CLIENT_TOKENS_WERENT_SET = 'Client\'s tokens weren\'t set';
		const SERVER_TOKENS_WERENT_SET = 'Server\'s tokens weren\'t set';
		const KEY_WASNT_SET            = 'Key wasn\'t set';
		const VECTOR_WASNT_SET         = 'Vector wasn\'t set';
		const MISSING_CLIENT_KEY       = 'Missing client\'s key';
		const MISSING_CLIENT_VECTOR    = 'Missing client\'s vector';
		const DECRYPT_DATA_IMPOSSIBLE  = 'Impossible to decrypt data!';
		const ENCRYPT_DATA_IMPOSSIBLE  = 'Impossible to encrypt data!';
		const DATA_WERENT_ENCRYPTED    = self::INTERNAL_ERROR . ' Data weren\'t encrypted';
		const DATA_WERENT_DECRYPTED    = self::INTERNAL_ERROR . ' Data weren\'t decrypted';
		const TOKENS_WERENT_DECRYPTED  = self::INTERNAL_ERROR . ' Tokens (key or vector) weren\'t decrypted';

		/**
		 * Method returns the instance of class
		 *
		 * @param array $options
		 *
		 * @return Encryption|null
		 * @throws EncryptionError
		 */
		public static function _( $options = [] ) {
			if ( !isset( self::$instance ) || !self::$instance instanceof self ) {
				return new self( $options );
			}
			else {
				return self::$instance;
			}
		}

		/**
		 * Encryption constructor.
		 *
		 * @param array $options
		 *
		 * @throws EncryptionError
		 */
		public function __construct( $options = [] ) {
			if ( !isset( self::$className ) ) {
				$self_class = explode( '\\', self::class );

				self::$className = end( $self_class );
			}

			if ( !isset( self::$lcClassName ) && !!self::$className ) {
				self::$lcClassName = strtolower( self::$className );
			}

			$this->setMode( empty( $options[ 'mode' ] ) ? null : $options[ 'mode' ] );
			$this->setLength( empty( $options[ 'length' ] ) ? null : $options[ 'length' ] );
			$this->setMethod( empty( $options[ 'method' ] ) ? null : $options[ 'method' ] );

			if ( !$this->initSession() ) {
				throw new EncryptionError( self::FAILED_TO_CONSTUCT_CLASS . ' ' . self::CLIENT_TOKENS_WERENT_SET );
			}

			if ( !$this->initStatic() ) {
				throw new EncryptionError( self::FAILED_TO_CONSTUCT_CLASS . ' ' . self::SERVER_TOKENS_WERENT_SET );
			}

			if ( !$this->generateKey() ) {
				throw new EncryptionError( self::FAILED_TO_CONSTUCT_CLASS . ' ' . self::KEY_WASNT_SET );
			}

			if ( !$this->generateVector() ) {
				throw new EncryptionError( self::FAILED_TO_CONSTUCT_CLASS . ' ' . self::VECTOR_WASNT_SET );
			}

			if ( !$this->encryptTokens() ) {
				throw new EncryptionError( self::FAILED_TO_CONSTUCT_CLASS . ' ' . self::PUBLIC_TOKENS_WERENT_SET );
			}

			if ( !isset( self::$instance ) || !self::$instance instanceof self ) {
				self::$instance = $this;
			}
		}

		/**
		 * Method sets key length
		 *
		 * @param int $length
		 */
		public function setLength( $length = 70 ) {
			$length = (int) $length;

			if ( !$length || $length < 10 ) {
				$length = 70;
			}

			$this->length = $length;
		}

		/**
		 * Method returns randomly generated client's key in binary or hexadecimal representations
		 * It needs to decrypt data
		 *
		 * @param bool $binary
		 *
		 * @return bool|string
		 * @throws EncryptionError
		 */
		public function getClientKey( $binary = false ) {
			if ( !is_bool( $binary ) ) {
				$binary = false;
			}

			$binary = !!$binary;

			$client_key = $_SESSION[ self::$lcClassName ][ 'key' ];

			if ( !$client_key || $client_key === false ) {
				throw new EncryptionError( self::MISSING_CLIENT_KEY );
			}

			return $binary ? $client_key : bin2hex( $client_key );
		}

		/**
		 * Method returns randomly generated client's vector in binary or hexadecimal representations
		 * It needs to decrypt data
		 *
		 * @param bool $binary
		 *
		 * @return bool|string|null
		 * @throws EncryptionError
		 */
		public function getClientVector( $binary = false ) {
			if ( !is_bool( $binary ) ) {
				$binary = false;
			}

			$binary = !!$binary;

			$client_vector = $_SESSION[ self::$lcClassName ][ 'vector' ];

			if ( !$client_vector || $client_vector === false ) {
				throw new EncryptionError( self::MISSING_CLIENT_VECTOR );
			}

			return $binary ? $client_vector : bin2hex( $client_vector );
		}

		/**
		 * If property $options[ 'once' ] has been passed
		 * Method encrypts data using newly generated key and vector
		 * It allows to developer encrypt same information with various key and vector
		 *
		 * Otherwise method encrypts data using generated key and vector
		 *
		 * @param Decrypted|mixed $data
		 * @param array           $options
		 *
		 * @return Encrypted
		 * @throws EncryptionError
		 */
		public function encrypt( $data, $options = [] ) {
			// parsing closures (functions or methods)
			if ( $data instanceof \Closure ) {
				for ( ; ; ) {
					if ( $data instanceof \Closure ) {
						$data = $data();
					}
					else {
						break;
					}
				}
			}

			$once = isset( $options[ 'once' ] ) ? !!$options[ 'once' ] : false;
			$data = serialize( $data );

			if ( isset( $options[ 'mode' ] ) && isset( $this->mode ) && $options[ 'mode' ] !== $this->mode ) {
				$this->setMode( $options[ 'mode' ] );
			}

			$result = Encrypted::_();
			$tokens = Tokens::_();

			$this->isKeySet();
			$this->isVectorSet();

			if ( $once ) {
				// current encrypted public tokens
				$current_key    = $this->key;
				$current_vector = $this->vector;

				$this->generateKey();
				$this->generateVector();
				$this->encryptTokens( $once );
			}

			$decrypted_tokens = $this->decryptTokens();

			if ( empty( $decrypted_tokens ) || empty( $decrypted_tokens[ 'key' ] ) || empty( $decrypted_tokens[ 'vector' ] ) ) {
				throw new EncryptionError( self::TOKENS_WERENT_DECRYPTED );
			}

			$encrypted = openssl_encrypt( $data, $this->method, $decrypted_tokens[ 'key' ], OPENSSL_RAW_DATA, $decrypted_tokens[ 'vector' ] );

			if ( !$encrypted || $encrypted === false ) {
				throw new EncryptionError( self::DATA_WERENT_ENCRYPTED );
			}

			$result->set( 'data', $encrypted );

			$tokens->set( 'public', [
				'key'    => $this->key,
				'vector' => $this->vector,
			] )
				->set( 'client', [
					'key'    => $this->getClientKey( true ),
					'vector' => $this->getClientVector( true ),
					'state'  => $this->getClientState(),
				] )
				->set( 'server', $this->getServerTokens( true ) )
				->close();

			$result->set( 'tokens', $tokens )
				->close();

			if ( $once && !empty( $current_key ) && !empty( $current_vector ) ) {
				$this->key    = $current_key;
				$this->vector = $current_vector;
			}

			return $result;
		}

		/**
		 * Method decrypts data using key and vector
		 *
		 * @param string|Encrypted            $data
		 * @param null|array|Tokens|Encrypted $tokens
		 *
		 * @return Decrypted
		 * @throws EncryptionError
		 */
		public function decrypt( $data, $tokens = null ) {
			if ( is_object( $data ) && $data instanceof Encrypted ) {
				if ( !$tokens instanceof Tokens ) {
					$tokens = $data->tokens();
				}

				$data = $data->getData();
			}

			if ( is_object( $tokens ) && !$tokens instanceof Tokens ) {
				if ( $tokens instanceof Encrypted ) {
					$tokens = $tokens->tokens();
				}
			}

			$data = $this->isBinary( $data ) ? $data : hex2bin( $data );

			$decrypted_tokens = $this->decryptTokens( isset( $tokens ) ? $tokens : null );

			if ( empty( $decrypted_tokens ) ) {
				throw new EncryptionError( self::TOKENS_WERENT_DECRYPTED );
			}

			$decrypted = openssl_decrypt( $data, $this->method, $decrypted_tokens[ 'key' ], OPENSSL_RAW_DATA, $decrypted_tokens[ 'vector' ] );

			if ( !$decrypted || $decrypted === false ) {
				throw new EncryptionError( self::DATA_WERENT_DECRYPTED );
			}

			return Decrypted::_()->set( 'data', unserialize( $decrypted ) )->close();
		}

		/**
		 * Method returns "true" if key has been set
		 * Otherwise it throws EncryptionError
		 *
		 * @return bool
		 * @throws EncryptionError
		 */
		private function isKeySet() {
			if ( !$this->key || $this->key === false ) {
				throw new EncryptionError( self::KEY_WASNT_SET );
			}

			return true;
		}

		/**
		 * Method returns "true" if vector has been set
		 * Otherwise it throws EncryptionError
		 *
		 * @return bool
		 * @throws EncryptionError
		 */
		private function isVectorSet() {
			if ( !$this->vector || $this->vector === false ) {
				throw new EncryptionError( self::VECTOR_WASNT_SET );
			}

			return true;
		}

		/**
		 * Method sets mode of encryption flow
		 *
		 * @param int|null $mode Picks only 3 values: CLIENT_MODE = 0, SERVER_MODE = 1 and CLIENT_SERVER_MODE = 2
		 *
		 * @throws EncryptionError
		 */
		private function setMode( $mode = null ) {
			if ( is_int( $mode ) && ( $mode === self::CLIENT_MODE || $mode === self::SERVER_MODE || $mode === self::CLIENT_SERVER_MODE ) ) {
				$this->mode = $mode;
			}
			else {
				if ( !isset( $this->mode ) ) {
					$this->mode = self::CLIENT_SERVER_MODE;
				}
			}

			if ( isset( self::$instance ) ) {
				$this->encryptTokens();
			}
		}

		/**
		 * Method sets encryption cipher method
		 *
		 * @param null|string $method
		 */
		private function setMethod( $method = null ) {
			$default = 'aes-256-cbc';

			if ( !is_string( $method ) || !$method ) {
				$this->method = $default;

				return;
			}

			if ( !function_exists( 'openssl_get_cipher_methods' ) ) {
				$this->method = $default;

				return;
			}

			$methods = openssl_get_cipher_methods();

			// ECB mode better to avoid
			$methods = array_filter( $methods, function( $m ) {
				return stripos( $m, 'ecb' ) === false;
			} );

			// get rid of weak methods
			$methods = array_filter( $methods, function( $m ) {
				return stripos( $m, 'des' ) === false;
			} );
			$methods = array_filter( $methods, function( $m ) {
				return stripos( $m, 'rc2' ) === false;
			} );
			$methods = array_filter( $methods, function( $m ) {
				return stripos( $m, 'rc4' ) === false;
			} );
			$methods = array_filter( $methods, function( $m ) {
				return stripos( $m, 'md5' ) === false;
			} );

			$is_valid_method = in_array( $method, $methods, true );

			if ( !isset( $is_valid_method ) || $is_valid_method === false ) {
				$this->method = $default;

				return;
			}

			$this->method = $method;
		}

		/**
		 * Method returns the server side bundle (key and vector)
		 *
		 * @param bool $binary
		 *
		 * @return false|array
		 */
		private function getServerTokens( $binary = false ) {
			$binary = !!$binary;

			if ( !file_exists( self::SERVER_TOKENS_FILE_PATH ) ) {
				return false;
			}

			$server_tokens_file = fopen( self::SERVER_TOKENS_FILE_PATH, 'rb' );
			$server_tokens      = unserialize( fgets( $server_tokens_file ) );

			fclose( $server_tokens_file );

			if ( !$server_tokens[ 'key' ] || !$server_tokens[ 'vector' ] ) {
				return false;
			}

			if ( !$binary ) {
				$server_tokens[ 'key' ]    = bin2hex( $server_tokens[ 'key' ] );
				$server_tokens[ 'vector' ] = bin2hex( $server_tokens[ 'vector' ] );
			}

			return $server_tokens;
		}

		/*
		 * Method sets the server side bundle (key and vector)
		 *
		 * @return bool
		 */
		private function setServerTokens() {
			$server_tokens_file = fopen( self::SERVER_TOKENS_FILE_PATH, 'w+' );

			$server_tokens = [
				'key'    => $this->generateToken( $this->length ),
				'vector' => $this->generateToken( openssl_cipher_iv_length( $this->method ) ),
			];

			if ( !$server_tokens[ 'key' ] || !$server_tokens[ 'vector' ] ) {
				return false;
			}

			fwrite( $server_tokens_file, serialize( $server_tokens ) );
			fclose( $server_tokens_file );

			return true;
		}

		/**
		 * Method sets client's key in binary representation
		 *
		 * @param string $key
		 *
		 * @return bool
		 */
		private function setClientKey( $key ) {
			if ( !is_string( $key ) ) {
				return false;
			}

			$_SESSION[ self::$lcClassName ][ 'key' ] = $this->isBinary( $key ) ? $key : hex2bin( $key );

			return true;
		}

		/**
		 * Method sets client's vector in binary representation
		 *
		 * @param string $vector
		 *
		 * @return bool
		 */
		private function setClientVector( $vector ) {
			if ( !is_string( $vector ) ) {
				return false;
			}

			$_SESSION[ self::$lcClassName ][ 'vector' ] = $this->isBinary( $vector ) ? $vector : hex2bin( $vector );

			return true;
		}

		/**
		 * Method sets client's "encrypted" flag
		 *
		 * @param bool $state
		 *
		 * @return bool
		 */
		private function setClientState( $state ) {
			if ( !is_bool( $state ) ) {
				return false;
			}

			$_SESSION[ self::$lcClassName ][ 'state' ] = $state;

			return true;
		}

		/**
		 * Method gets client's "encrypted" flag
		 *
		 * @return bool|null
		 */
		private function getClientState() {
			if ( !isset( $_SESSION[ self::$lcClassName ][ 'state' ] ) || !is_bool( $_SESSION[ self::$lcClassName ][ 'state' ] ) ) {
				return null;
			}

			return $_SESSION[ self::$lcClassName ][ 'state' ];
		}

		/**
		 * Method generates and sets new randomly generated encryption key
		 *
		 * @return bool
		 */
		private function generateKey() {
			if ( !!$this->key ) {
				$this->key = '';
			}

			$this->key = $this->generateToken( $this->length );

			if ( !$this->key ) {
				return false;
			}

			return true;
		}

		/**
		 * Method generates and sets new randomly generated encryption vector
		 *
		 * @return bool
		 */
		private function generateVector() {
			if ( !!$this->vector ) {
				$this->vector = '';
			}

			$this->vector = $this->generateToken( openssl_cipher_iv_length( $this->method ) );

			if ( !$this->vector ) {
				return false;
			}

			return true;
		}

		/**
		 * Method generates cryptographically secure pseudo-random token
		 *
		 * PHP version >5.0 strongly recommended
		 *
		 * @param int $length
		 *
		 * @return string|void|null
		 */
		private function generateToken( $length = 70 ) {
			if ( function_exists( 'random_bytes' ) ) {
				try {
					return random_bytes( $length );
				}
				catch ( \Exception $exception ) {
					return openssl_random_pseudo_bytes( $length );
				}
			}
			else if ( function_exists( 'openssl_random_pseudo_bytes' ) ) {
				return openssl_random_pseudo_bytes( $length );
			}
			else {
				return false;
			}
		}

		/**
		 * Method encrypts the public tokens to encrypt/decrypt data
		 *
		 * @param bool $once When it's true method won't try to decrypt public tokens
		 *
		 * @return bool
		 * @throws EncryptionError
		 */
		private function encryptTokens( $once = false ) {
			if ( !isset( $this->mode ) ) {
				return false;
			}

			if ( isset( self::$instance ) && !$once ) {
				$decrypted_tokens = $this->decryptTokens();

				if ( empty( $decrypted_tokens ) || empty( $decrypted_tokens[ 'key' ] ) || empty( $decrypted_tokens[ 'vector' ] ) ) {
					return false;
				}

				$this->key    = $decrypted_tokens[ 'key' ];
				$this->vector = $decrypted_tokens[ 'vector' ];
			}

			switch ( $this->mode ) {
				case self::CLIENT_MODE || self::CLIENT_SERVER_MODE:
					$client_key    = $this->getClientKey( true );
					$client_vector = $this->getClientVector( true );
					$client_state  = $this->getClientState();
					$server_tokens = $this->getServerTokens( true );

					if ( !$this->key || !$this->vector || !$client_key || !$client_vector || !isset( $client_state ) || !$server_tokens[ 'key' ] || !$server_tokens[ 'vector' ] ) {
						return false;
					}

					if ( $client_state ) {
						$this->setClientKey( openssl_decrypt( $client_key, $this->method, $server_tokens[ 'key' ], OPENSSL_RAW_DATA, $server_tokens[ 'vector' ] ) );
						$this->setClientVector( openssl_decrypt( $client_vector, $this->method, $server_tokens[ 'key' ], OPENSSL_RAW_DATA, $server_tokens[ 'vector' ] ) );

						$client_key    = $this->getClientKey( true );
						$client_vector = $this->getClientVector( true );

						if ( !$client_key || $client_key === false || !$client_vector || $client_vector === false ) {
							return false;
						}

						$this->setClientState( false );
					}

					$this->key    = openssl_encrypt( $this->key, $this->method, $client_key, OPENSSL_RAW_DATA, $client_vector );
					$this->vector = openssl_encrypt( $this->vector, $this->method, $client_key, OPENSSL_RAW_DATA, $client_vector );

					if ( !$this->key || $this->key === false || !$this->vector || $this->vector === false ) {
						return false;
					}

					if ( $this->mode === self::CLIENT_SERVER_MODE ) {
						$this->setClientKey( openssl_encrypt( $client_key, $this->method, $server_tokens[ 'key' ], OPENSSL_RAW_DATA, $server_tokens[ 'vector' ] ) );
						$this->setClientVector( openssl_encrypt( $client_vector, $this->method, $server_tokens[ 'key' ], OPENSSL_RAW_DATA, $server_tokens[ 'vector' ] ) );

						$client_key    = $this->getClientKey( true );
						$client_vector = $this->getClientVector( true );

						if ( !$client_key || $client_key === false || !$client_vector || $client_vector === false ) {
							return false;
						}

						$this->setClientState( true );
					}

					return true;

				case self::SERVER_MODE:
					$server_tokens = $this->getServerTokens( true );

					if ( !$this->key || !$this->vector || !$server_tokens[ 'key' ] || !$server_tokens[ 'vector' ] ) {
						return false;
					}

					$this->key    = openssl_encrypt( $this->key, $this->method, $server_tokens[ 'key' ], OPENSSL_RAW_DATA, $server_tokens[ 'vector' ] );
					$this->vector = openssl_encrypt( $this->vector, $this->method, $server_tokens[ 'key' ], OPENSSL_RAW_DATA, $server_tokens[ 'vector' ] );

					if ( !$this->key || $this->key === false || !$this->vector || $this->vector === false ) {
						return false;
					}

					return true;

				default:
					return false;
			}
		}

		/**
		 * Method decrypts the public tokens to encrypt/decrypt data
		 *
		 * @param null|Tokens|array $tokens
		 *
		 * @return false|array
		 * @throws EncryptionError
		 */
		private function decryptTokens( $tokens = null ) {
			if ( $tokens instanceof Tokens ) {
				$tokens = $tokens->get( null, null, true );
			}

			if ( $this->isSerialized( $tokens ) ) {
				$tokens = unserialize( $tokens );
			}

			if ( empty( $tokens ) || ( !is_array( $tokens ) && !$tokens instanceof Tokens ) ) {
				$tokens = [
					'public' => [
						'key'    => $this->key,
						'vector' => $this->vector,
					],
					'client' => [
						'key'    => $this->getClientKey( true ),
						'vector' => $this->getClientVector( true ),
						'state'  => $this->getClientState(),
					],
					'server' => $this->getServerTokens( true ),
				];
			}
			else if ( is_array( $tokens ) ) {
				if ( empty( $tokens[ 'public' ] ) ) {
					$tokens[ 'public' ] = [
						'key'    => $this->key,
						'vector' => $this->vector,
					];
				}
				else {
					if ( !empty( $tokens[ 'public' ][ 'key' ] ) ) {
						$tokens[ 'public' ][ 'key' ] = $this->isBinary( $tokens[ 'public' ][ 'key' ] ) ? $tokens[ 'public' ][ 'key' ] : hex2bin( $tokens[ 'public' ][ 'key' ] );
					}
					else {
						$tokens[ 'public' ][ 'key' ] = $this->key;
					}

					if ( !empty( $tokens[ 'public' ][ 'vector' ] ) ) {
						$tokens[ 'public' ][ 'vector' ] = $this->isBinary( $tokens[ 'public' ][ 'vector' ] ) ? $tokens[ 'public' ][ 'vector' ] : hex2bin( $tokens[ 'public' ][ 'vector' ] );
					}
					else {
						$tokens[ 'public' ][ 'vector' ] = $this->vector;
					}
				}

				if ( empty( $tokens[ 'client' ] ) ) {
					$tokens[ 'client' ] = [
						'key'    => $this->getClientKey( true ),
						'vector' => $this->getClientVector( true ),
						'state'  => $this->getClientState(),
					];
				}
				else {
					if ( !empty( $tokens[ 'client' ][ 'key' ] ) ) {
						$tokens[ 'client' ][ 'key' ] = $this->isBinary( $tokens[ 'client' ][ 'key' ] ) ? $tokens[ 'client' ][ 'key' ] : hex2bin( $tokens[ 'client' ][ 'key' ] );
					}
					else {
						$tokens[ 'client' ][ 'key' ] = $this->getClientKey( true );
					}

					if ( !empty( $tokens[ 'client' ][ 'vector' ] ) ) {
						$tokens[ 'client' ][ 'vector' ] = $this->isBinary( $tokens[ 'client' ][ 'vector' ] ) ? $tokens[ 'client' ][ 'vector' ] : hex2bin( $tokens[ 'client' ][ 'vector' ] );
					}
					else {
						$tokens[ 'client' ][ 'vector' ] = $this->getClientVector( true );
					}

					if ( !isset( $tokens[ 'client' ][ 'state' ] ) ) {
						$tokens[ 'client' ][ 'state' ] = $this->getClientState();
					}
					else if ( isset( $tokens[ 'client' ][ 'state' ] ) && !is_bool( $tokens[ 'client' ][ 'state' ] ) ) {
						throw new EncryptionError( self::INTERNAL_ERROR . ' ' . 'Client state is incorrect!' );
					}
				}

				$server_tokens = $this->getServerTokens( true );

				if ( empty( $tokens[ 'server' ] ) ) {
					$tokens[ 'server' ] = $server_tokens;
				}
				else {
					if ( !empty( $tokens[ 'server' ][ 'key' ] ) ) {
						$tokens[ 'server' ][ 'key' ] = $this->isBinary( $tokens[ 'server' ][ 'key' ] ) ? $tokens[ 'server' ][ 'key' ] : hex2bin( $tokens[ 'server' ][ 'key' ] );
					}
					else {
						$tokens[ 'server' ][ 'key' ] = $server_tokens[ 'key' ];
					}

					if ( !empty( $tokens[ 'server' ][ 'vector' ] ) ) {
						$tokens[ 'server' ][ 'vector' ] = $this->isBinary( $tokens[ 'server' ][ 'vector' ] ) ? $tokens[ 'server' ][ 'vector' ] : hex2bin( $tokens[ 'server' ][ 'vector' ] );
					}
					else {
						$tokens[ 'server' ][ 'vector' ] = $server_tokens[ 'vector' ];
					}
				}
			}
			else {
				return false;
			}

			$is_keys_decrypted = false;
			$decrypted_tokens  = null;

			for ( $index = 0; !$is_keys_decrypted; $index++ ) { // if you think this is infinity loop know you're wrong
				switch ( $index ) {
					case 0:
						// if client's tokens were encrypted decrypt them
						if ( $tokens[ 'client' ][ 'state' ] ) {
							$tokens[ 'client' ][ 'key' ]    = openssl_decrypt( $tokens[ 'client' ][ 'key' ], $this->method, $tokens[ 'server' ][ 'key' ], OPENSSL_RAW_DATA, $tokens[ 'server' ][ 'vector' ] );
							$tokens[ 'client' ][ 'vector' ] = openssl_decrypt( $tokens[ 'client' ][ 'vector' ], $this->method, $tokens[ 'server' ][ 'key' ], OPENSSL_RAW_DATA, $tokens[ 'server' ][ 'vector' ] );

							if ( !$tokens[ 'client' ][ 'key' ] || !$tokens[ 'client' ][ 'vector' ] ) {
								break;
							}
						}

						$decrypted_tokens = [
							'key'    => openssl_decrypt( $tokens[ 'public' ][ 'key' ], $this->method, $tokens[ 'client' ][ 'key' ], OPENSSL_RAW_DATA, $tokens[ 'client' ][ 'vector' ] ),
							'vector' => openssl_decrypt( $tokens[ 'public' ][ 'vector' ], $this->method, $tokens[ 'client' ][ 'key' ], OPENSSL_RAW_DATA, $tokens[ 'client' ][ 'vector' ] ),
						];

						if ( ( !$decrypted_tokens[ 'key' ] || $decrypted_tokens[ 'key' ] === false ) && ( !$decrypted_tokens[ 'vector' ] || $decrypted_tokens[ 'vector' ] === false ) ) {
							break;
						}

						$is_keys_decrypted = true;
						break;

					case 1:
						if ( empty( $tokens[ 'public' ][ 'key' ] ) || empty( $tokens[ 'public' ][ 'vector' ] ) || empty( $tokens[ 'server' ][ 'key' ] ) || empty( $tokens[ 'server' ][ 'vector' ] ) ) {
							break;
						}

						$decrypted_tokens = [
							'key'    => openssl_decrypt( $tokens[ 'public' ][ 'key' ], $this->method, $tokens[ 'server' ][ 'key' ], OPENSSL_RAW_DATA, $tokens[ 'server' ][ 'vector' ] ),
							'vector' => openssl_decrypt( $tokens[ 'public' ][ 'vector' ], $this->method, $tokens[ 'server' ][ 'key' ], OPENSSL_RAW_DATA, $tokens[ 'server' ][ 'vector' ] ),
						];

						if ( ( !$decrypted_tokens[ 'key' ] || $decrypted_tokens[ 'key' ] === false ) && ( !$decrypted_tokens[ 'vector' ] || $decrypted_tokens[ 'vector' ] === false ) ) {
							break;
						}

						$is_keys_decrypted = true;
						break;

					default:
						$is_keys_decrypted = true; // setting flag to prevent infinity loop
						break; // unnecessary but it can to lie down there for a while
				}
			}

			return empty( $decrypted_tokens ) ? false : $decrypted_tokens;
		}

		/**
		 * Method verifies is flashed string in binary representation
		 *
		 * @param $string
		 *
		 * @return bool
		 */
		private function isBinary( $string ) {
			return preg_match( '~[^\x20-\x7E\t\r\n]~', $string ) > 0;
		}

		/**
		 * Check value to find if it was serialized.
		 *
		 * If $data is not an string, then returned value will always be false.
		 * Serialized data is always a string.
		 *
		 * @param string $data   Value to check to see if was serialized.
		 * @param bool   $strict Optional. Whether to be strict about the end of the string. Default true.
		 *
		 * @return bool False if not serialized and true if it was.
		 * @since 1.3.0.6
		 *
		 */
		private function isSerialized( $data, $strict = true ) {
			// if it isn't a string, it isn't serialized.
			if ( !is_string( $data ) ) {
				return false;
			}
			$data = trim( $data );
			if ( 'N;' == $data ) {
				return true;
			}
			if ( strlen( $data ) < 4 ) {
				return false;
			}
			if ( ':' !== $data[ 1 ] ) {
				return false;
			}
			if ( $strict ) {
				$lastc = substr( $data, -1 );
				if ( ';' !== $lastc && '}' !== $lastc ) {
					return false;
				}
			}
			else {
				$semicolon = strpos( $data, ';' );
				$brace     = strpos( $data, '}' );
				// Either ; or } must exist.
				if ( false === $semicolon && false === $brace ) {
					return false;
				}
				// But neither must be in the first X characters.
				if ( false !== $semicolon && $semicolon < 3 ) {
					return false;
				}
				if ( false !== $brace && $brace < 4 ) {
					return false;
				}
			}
			$token = $data[ 0 ];
			switch ( $token ) {
				case 's':
					if ( $strict ) {
						if ( '"' !== substr( $data, -2, 1 ) ) {
							return false;
						}
					}
					else if ( false === strpos( $data, '"' ) ) {
						return false;
					}
				// or else fall through
				case 'a':
				case 'O':
					return (bool) preg_match( "/^{$token}:[0-9]+:/s", $data );
				case 'b':
				case 'i':
				case 'd':
					$end = $strict ? '$' : '';

					return (bool) preg_match( "/^{$token}:[0-9.E-]+;$end/", $data );
			}

			return false;
		}

		/**
		 * Method initiates client's session
		 *
		 * @throws EncryptionError
		 */
		private function initSession() {
			if ( php_sapi_name() === 'cli' ) {
				return true;
			}

			if ( session_status() === PHP_SESSION_NONE ) {
				if ( version_compare( PHP_VERSION, '7.0.0', '>=' ) ) {
					session_start( [
						'name' => self::$className . 'SID',
					] );
				}
				else {
					session_name( self::$className . 'SID' );
					session_start();
				}
			}

			session_regenerate_id();

			$client_state = $this->getClientState();

			if ( !$_SESSION || !$this->getClientKey() || !$this->getClientVector() || !isset( $client_state ) ) {
				$this->setClientKey( $this->generateToken( $this->length ) );
				$this->setClientVector( $this->generateToken( openssl_cipher_iv_length( $this->method ) ) );
				$this->setClientState( false );

				if ( !$this->getClientKey() || !$this->getClientVector() ) {
					return false;
				}

				session_write_close();
			}

			return true;
		}

		/**
		 * Method initiates server side tokens for static encryption methods
		 *
		 * @return bool
		 */
		private function initStatic() {
			if ( !file_exists( self::SERVER_TOKENS_FILE_PATH ) ) {
				$this->setServerTokens();
			}
			else {
				$server_tokens = $this->getServerTokens( true );

				if ( !$server_tokens ) {
					$this->setServerTokens();
				}
			}

			return true;
		}
	}