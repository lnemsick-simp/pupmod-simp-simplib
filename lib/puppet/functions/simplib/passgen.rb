# Generates/retrieves a random password string or its hash for a
# passed identifier.
#
# * Persists the passwords using libkv.
# * The minimum length password that this function will return is `8`
#   characters.
# * Terminates catalog compilation if any libkv operation fails or the password
#   cannot be created in the allotted time.
#
Puppet::Functions.create_function(:'simplib::passgen') do

  # @param identifier Unique `String` to identify the password usage.
  #   Must conform to the following:
  #   * Identifier must contain only the following characters:
  #     * a-z
  #     * A-Z
  #     * 0-9
  #     * The following special characters: `._:-/`
  #   * Identifier may not contain '/./' or '/../' sequences.
  #
  # @param password_options
  #   Password options
  #
  # @option password_options [Boolean] 'last'
  #   Whether to return the last generate password.
  #   Defaults to `false`.
  # @option password_options [Integer[8]] 'length'
  #   Length of the new password.
  #   Defaults to `32`.
  # @option password_options [Enum[true,false,'md5',sha256','sha512']] 'hash'
  #   Return a `Hash` of the password instead of the password itself.
  #   Defaults to `false`.  `true` is equivalent to 'sha256'.
  # @option password_options [Integer[0,2]] 'complexity'
  #   Specifies the types of characters to be used in the password
  #     * `0` => Default. Use only Alphanumeric characters in your password (safest)
  #     * `1` => Add reasonably safe symbols
  #     * `2` => Printable ASCII
  # @option password_options [Boolean] 'complex_only'
  #   Whether to use only the characters explicitly added by the complexity rules.
  #   For example, when `complexity` is `1`, create a password from only safe symbols.
  #   Defaults to `false`.
  # @option password_options [Variant[Integer[0],Float[0]]] 'gen_timeout_seconds'
  #   Maximum time allotted to generate the password.
  #     * Value of `0` disables the timeout.
  #     * Defaults to `30`.
  #
  # @param libkv_options Hash that specifies global libkv options and/or
  #   the specific backend to use (with or without backend-specific
  #   configuration). Will be merged with `libkv::options`.
  #
  # @option libkv_options [Hash] 'backends'
  #   Hash of backend configurations
  #
  #     * Each backend configuration in the merged options Hash must be
  #       a Hash that has the following keys:
  #
  #       * `type`:  Backend type.
  #       * `id`:  Unique name for the instance of the backend. (Same backend
  #         type can be configured differently).
  #
  #      * Other keys for configuration specific to the backend may also be
  #        present.
  #
  # @option libkv_options [String] 'backend'
  #   Name of the backend to use.
  #
  #     * When present, must match a key in the `backends` option of the
  #       merged options Hash.
  #     * When absent and not specified in `libkv::options`, this function
  #       will look for a 'default.xxx' backend whose name matches the
  #       `resource` option.  This is typically the catalog resource id of the
  #       calling Class, specific defined type instance, or defined type.
  #       If no match is found, it will use the 'default' backend.
  #
  # @option libkv_options [String] 'environment'
  #   Puppet environment to prepend to keys.
  #
  #     * When set to a non-empty string, it is prepended to the key used in
  #       the backend operation.
  #     * Should only be set to an empty string when the key being accessed is
  #       truly global.
  #     * Defaults to the Puppet environment for the node.
  #
  # @option libkv_options [String] 'resource'
  #   Name of the Puppet resource initiating this libkv operation
  #
  #     * Required when `backend` is not specified and you want to be able
  #       to use more than the `default` backend.
  #     * String should be resource as it would appear in the catalog or
  #       some application grouping id
  #
  #       * 'Class[<class>]' for a class, e.g.  'Class[Mymodule::Myclass]'
  #       * '<Defined type>[<instance>]' for a defined type instance, e.g.,
  #         'Mymodule::Mydefine[myinstance]'
  #
  #     * Catalog resource id cannot be reliably determined automatically.
  #       Appropriate scope is not necessarily available when a libkv function
  #       is called within any other function.  This is problematic for heavily
  #       used Puppet built-in functions such as `each`.
  #
  # @option libkv_options [Boolean] 'softfail'
  #  Whether to ignore libkv operation failures.
  #
  #    * When `true`, this function will return a result even when the operation
  #      failed at the backend.
  #    * When `false`, this function will fail when the backend operation failed.
  #    * Defaults to `false`.
  #
  # @return [String] Password or password hash specified.
  #
  #   * When the `last` password option is `true`, the password is determined
  #     as follows:
  #
  #     * If the last password exists in the key/value store, uses the existing
  #       last password.
  #     * Otherwise, if the current password exists in the key/value store,
  #       uses the existing current password.
  #     * Otherwise, creates and stores a new password as the current password,
  #       and then uses this new password
  #
  #   * When `last` option is `false`, the password is determined as follows:
  #
  #     * If the current password doesn't exist in the key/value store, creates
  #       and stores a new password as the current password, and then uses this
  #       new password.
  #     * Otherwise, if the current password exists in the key/value store and it
  #       has an appropriate length, uses the current password.
  #     * Otherwise, stores the current password as the last password, creates
  #       and stores a new password as the current password, and then uses this
  #       new password.
  #
  # @raise Exception if `password_options` contains invalid parameters,
  #   a libkv operation fails, or password generation times out
  #
  dispatch :passgen do
    required_param 'String[1]', :identifier
    optional_param 'Hash',      :password_options
    optional_param 'Hash',      :libkv_options
  end

  def passgen(identifier, password_options=nil, libkv_options={'resource' => 'passgen'})
    require 'etc'
    require 'timeout'

    # internal settings
    settings = {}
    settings['key_root_dir'] = 'gen_passwd'
    settings['min_password_length'] = 8
    settings['default_password_length'] = 32
    settings['crypt_map'] = {
      'md5'     => '1',
      'sha256'  => '5',
      'sha512'  => '6'
    }

    base_options = {
      'last'                => false,
      'length'              => settings['default_password_length'],
      'hash'                => false,
      'complexity'          => 0,
      'complex_only'        => false,
      'gen_timeout_seconds' => 30,

      # internal options
      'length_configured'   => false,
      'key_root_dir'        => settings['key_root_dir']
    }

    options = build_options(base_options, password_options, settings)

    password = nil
    salt = nil
    begin
      if options['last']
        password,salt = get_last_password(identifier, options, libkv_options)
      else
        password,salt = get_current_password(identifier, options, libkv_options)
      end
    rescue Timeout::Error => e
      # can get here if simplib::gen_random_password times out
      fail("simplib::passgen timed out for '#{identifier}'!")
    end

    # Return the hash, not the password
    if options['hash']
      return password.crypt("$#{settings['crypt_map'][options['hash']]}$#{salt}")
    else
      return password
    end
  end


  # Build a merged options hash and validate the options
  # @raise ArgumentError if any option in the password_options is invalid
  def build_options(base_options, password_options, settings)
    options = base_options.dup
    return options if password_options.nil?

    options.merge!(password_options)
    options['length_configured'] = true if password_options['length']

    if options['length'].to_s !~ /^\d+$/
      raise ArgumentError,
        "simplib::passgen: Error: Length '#{options['length']}' must be an integer!"
    else
      options['length'] = options['length'].to_i
      if options['length'] == 0
        options['length'] = settings['default_password_length']
      elsif options['length'] < settings['min_password_length']
        options['length'] = settings['min_password_length']
      end
    end

    if options['complexity'].to_s !~ /^\d+$/
      raise ArgumentError,
        "simplib::passgen: Error: Complexity '#{options['complexity']}' must be an integer!"
    else
      options['complexity'] = options['complexity'].to_i
    end

    # Make sure a valid hash has been selected
    if options['hash'] == true
      options['hash'] = 'sha256'
    end
    if options['hash'] and !settings['crypt_map'].keys.include?(options['hash'])
      raise ArgumentError,
       "simplib::passgen: Error: '#{options['hash']}' is not a valid hash."
    end

    return options
  end

  # Create a <password,salt> pair and then store it in the key/value store
  # @return [password, salt]
  def create_and_store_password(password_key, options, libkv_options)
    password = gen_password(options)
    salt = gen_salt(options)
    store_password_info(password, salt, password_key, libkv_options)
    [password, salt]
  end

  # Generate a password
  # @raise Timeout::Error if password generation times out (30 seconds)
  def gen_password(options)
    call_function('simplib::gen_random_password',
      options['length'],
      options['complexity'],
      options['complex_only'],
      options['gen_timeout_seconds']
    )
  end

  # Generate the salt to be used to encrypt a password
  # @raise Timeout::Error if password generation times out
  def gen_salt(options)
    # complexity of 0 is required to prevent disallowed
    # characters from being included in the salt
    call_function('simplib::gen_random_password',
      16,    # length
      0,     # complexity
      false, # complex_only
      options['gen_timeout_seconds']
    )
  end

  # Retrieve or generate a current password and its salt
  #
  # * If the current password doesn't exist in the key/value store, generate
  #   both the password and its salt and store them in the key/value store.
  # * If the current password exists, retrieve it and its salt from the
  #   key/value store, and validate it.
  #   * If the password has the correct length per the options, use it.
  #   * Otherwise, store this password and its salt as the last password in
  #     the key/value store, generate a new the password and salt, and then
  #     store the new values as the current password in the key/value store.
  #
  # @return current [password, salt]
  # @raise if any libkv operation fails or password/salt generation times out.
  #
  def get_current_password(identifier, options, libkv_options)
    current_key = "#{options['key_root_dir']}/#{identifier}"
    password = nil
    salt = nil
    generate = false
    if call_function('libkv::exists', current_key, libkv_options)
      password, salt = retrieve_password_info(current_key, libkv_options)
      unless valid_length?(password, options)
        # store old password
        last_key = "#{current_key}.last"
        store_password_info(password, salt, last_key, libkv_options)
        generate = true
      end
    else
      generate = true
    end

    if generate
      password, salt = create_and_store_password(current_key, options,
        libkv_options)
    end

    [password, salt]
  end

  # Retrieve lastest password and its salt, generating the password
  # if needed
  #
  #  * If the last password key exists in the key/value store, retrieve
  #    it and its salt from the store.
  #  * Otherwise, if the current password key exists in the key/value
  #    store, retrieve it and its salt from the store.
  #  * Otherwise, create a freshly-generated password and salt, store it
  #    in the key/value store and warn the user about a probable manifest
  #    ordering problems.
  #
  # @return last [password, salt]
  # @raise if any libkv operation fails or password/salt generation times out.
  #
  def get_last_password(identifier, options, libkv_options)
    current_key = "#{options['key_root_dir']}/#{identifier}"
    last_key = "#{current_key}.last"
    password = nil
    salt = nil
    if call_function('libkv::exists', last_key, libkv_options)
      password, salt = retrieve_password_info(last_key, libkv_options)
    elsif call_function('libkv::exists', current_key, libkv_options)
      password, salt = retrieve_password_info(current_key, libkv_options)
    else
      warn_msg = "Could not retrieve a last or current value for" +
        " #{identifier}. Generating a new value for 'last'. Please ensure" +
        " that you have used simplib::passgen in the proper order in your" +
        " manifest!"
      Puppet.warning warn_msg
      # generate password and salt
      password = gen_password(options),
      salt = gen_salt
      store_password_info(password, salt, last_key, libkv_options)
    end

    [password, salt]
  end

  # @return whether password length conforms to user specification
  def valid_length?(password, options)
    if options['length_configured']
      valid = (password.length == options['length'])
    else
      valid = true
    end

    valid
  end

  # @return [password, salt] retrieved from the key/value store
  def retrieve_password_info(password_key, libkv_options)
    key_info = call_function('libkv::get', password_key, libkv_options)['value']
    password = key_info['password']
    salt = key_info['salt']

    [password, salt]
  end

  # store a password and its salt in the key/value store
  def store_password_info(password, salt, password_key, libkv_options)
    key_info = { 'password' => password, 'salt' => salt }
    metadata = {}
    call_function('libkv::put', password_key, key_info, metadata, libkv_options)
  end
end
