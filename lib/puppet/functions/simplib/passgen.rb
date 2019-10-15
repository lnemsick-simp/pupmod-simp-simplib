# Generates/retrieves a random password string or its hash for a
# passed identifier.
#
# * Persists the passwords using libkv.
# * Migrates any passwords from non-libkv versions of `simplib::passgen`
#   into libkv.
# * The minimum length password that this function will return is `8`
#   characters.
# * Terminates catalog compilation if `password_options` contains invalid
#   parameters, any libkv operation fails or the password cannot be created
#   in the allotted time.
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
  #   Whether to return the last generated password.
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
  #   Maximum time allotted to generate or migrate the password.
  #     * Value of `0` disables the timeout.
  #     * Defaults to `30`.
  #
  # @param libkv_options libkv configuration that will be merged with
  #   `libkv::options`.  All keys are optional.
  #
  # @option libkv_options [String] 'app_id'
  #   Specifies an application name that can be used to identify which backend
  #   configuration to use via fuzzy name matching, in the absence of the
  #   `backend` option.
  #
  #     * More flexible option than `backend`.
  #     * Useful for grouping together libkv function calls found in different
  #       catalog resources.
  #     * When specified and the `backend` option is absent, the backend will be
  #       selected preferring a backend in the merged `backends` option whose
  #       name exactly matches the `app_id`, followed by the longest backend
  #       name that matches the beginning of the `app_id`, followed by the
  #       `default` backend.
  #     * When absent and the `backend` option is also absent, this function
  #       will use the `default` backend.
  #
  # @option libkv_options [String] 'backend'
  #   Definitive name of the backend to use.
  #
  #     * Takes precedence over `app_id`.
  #     * When present, must match a key in the `backends` option of the
  #       merged options Hash or the function will fail.
  #     * When absent in the merged options, this function will select
  #       the backend as described in the `app_id` option.
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
  # @option libkv_options [String] 'environment'
  #   Puppet environment to prepend to keys.
  #
  #     * When set to a non-empty string, it is prepended to the key used in
  #       the backend operation.
  #     * Should only be set to an empty string when the key being accessed is
  #       truly global.
  #     * Defaults to the Puppet environment for the node.
  #
  # @option libkv_options [Boolean] 'softfail'
  #   Whether to ignore libkv operation failures.
  #
  #     * When `true`, this function will return a result even when the
  #       operation failed at the backend.
  #     * When `false`, this function will fail when the backend operation
  #       failed.
  #     * Defaults to `false`.
  #
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
  #   a libkv operation fails, or password generation or migration times out
  #
  dispatch :passgen do
    required_param 'String[1]', :identifier
    optional_param 'Hash',      :password_options
    optional_param 'Hash',      :libkv_options
  end

  def passgen(identifier, password_options={}, libkv_options={'app_id' => 'simplib::passgen'})
    require 'timeout'

    scope = closure_scope

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

    # location of key and salt files in non-libkv versions of simplib::passgen
    settings['legacy_key_dir'] = File.join(Puppet.settings[:vardir], 'simp',
      'environments', scope.lookupvar('::environment'),
      'simp_autofiles', 'gen_passwd'
    )

    base_options = {
      'last'                => false,
      'length'              => settings['default_password_length'],
      'hash'                => false,
      'complexity'          => 0,
      'complex_only'        => false,
      'gen_timeout_seconds' => 30
    }

    options = build_options(base_options, password_options, settings)

    password = nil
    salt = nil
    begin
      migrate_old_files(identifier, options, libkv_options)

      if options['last']
        password,salt = get_last_password(identifier, options, libkv_options)
      else
        password,salt = get_current_password(identifier, options, libkv_options)
      end
    rescue Timeout::Error => e
      # can get here if simplib::gen_random_password or migrate_old_files
      # times out
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
    options.merge!(password_options)

    # set internal options
    options['length_configured'] = password_options.has_key?('length')
    options['key_root_dir']      = settings['key_root_dir']
    options['legacy_key_dir']    = settings['legacy_key_dir']

    # validate
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
    store_password_info(password, salt, options, password_key, libkv_options)
    [password, salt]
  end

  # Generate a password
  # @raise Timeout::Error if password generation times out
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
      # TODO Should we validate the length, complexity and complex_only settings
      # still match settings persisted with last password?  Couldn't do that
      # with the legacy simplib::passgen implementation, but could do that now!
      unless valid_length?(password, options)
        # store old password
        last_key = "#{current_key}.last"
        store_password_info(password, salt, options, last_key, libkv_options)
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
      # generate password and salt and then store
      password, salt = create_and_store_password(last_key, options,
        libkv_options)
    end

    [password, salt]
  end

  # Read in/generate the legacy salt
  #
  # Creates a legacy salt file if the file does not exist or the salt is empty.
  #
  # @return salt
  def get_legacy_salt(salt_file, options)
    create_legacy_salt_file = false
    if File.exist?(salt_file)
      salt = IO.readlines(salt_file)[0].to_s.chomp
      create_legacy_salt_file = true if salt.empty?
    else
      create_legacy_salt_file = true
    end

    if create_legacy_salt_file
      salt = gen_salt(options)
      file = File.new(salt_file,'w')
      file.puts(salt)
      file.flush
      file.close
      FileUtils.chmod(0660, salt_file)
    end

    salt
  end

  # Migrate any existing key and salt files for the identifier into libkv
  #
  # BACKGROUND
  # Migration is a little tricky in two scenarios:
  # - A user changes the password using a legacy version of `simp passgen` that
  #   only operates on password files in the legacy password directory.
  # - More than one environment has been using the same legacy password
  #   directory (e.g., via directory links) and at least one of those
  #   environments is still using a version of simplib::passgen that does not
  #   use libkv.
  #
  # In these cases, instead of just importing the password info into libkv once
  # for an environment, this code has to make sure any already imported password
  # is current.  If it was updated using legacy methods, the old value must be
  # stored as a 'last' value and the new value must be stored as the 'current'
  # value.
  #
  # Another relevant OBTW that can't be solved without bug fixes to legacy code
  # is that the legacy password files could be in the process of being modified
  # when we read them here.  Neither legacy `simplib::passgen` or `simp passgen`
  # employed any file locking to prevent this problem.
  #
  # MIGRATION ALGORITHM
  #
  # * Stores the current password and salt in libkv, when the files exist.
  # * Stores the last password and salt in libkv, when the files exist.
  # * Archives processed files.
  # * When a password is missing its salt file or the salt is empty, generates
  #   a salt for it before storing in libkv.
  # * When the password file is missing or the password is empty, removes
  #   the files, as they cannot be used.
  #
  # @raise Exception if cannot retrieve migration lock or any libkv store fails
  def migrate_old_files(identifier, options, libkv_options)
    return if Dir.glob(File.join(options['legacy_key_dir'], "#{identifier}*")).empty?

    file = nil
    begin
      # To ensure all threads are not sharing the same file descriptor
      # do **NOT** use a File.open block!
      lockfile = File.join(options['legacy_key_dir'], '.migrate')
      file = File.open(lockfile, 'w')

      Timeout::timeout(options['gen_timeout_seconds']) do
        file.flock(File::LOCK_EX)
      end

      current      = File.join(options['legacy_key_dir'], identifier)
      current_salt = File.join(options['legacy_key_dir'], "#{identifier}.salt")
      current_key  = "#{options['key_root_dir']}/#{identifier}"
      migrate_old_file_pair(current, current_salt, current_key, options,
        libkv_options)

      last      = File.join(options['legacy_key_dir'], "#{identifier}.last")
      last_salt = File.join(options['legacy_key_dir'], "#{identifier}.salt.last")
      last_key  = "#{current_key}.last"
      migrate_old_file_pair(last, last_salt, last_key, options, libkv_options)

    ensure
      unless file.nil?
        file.close # lock released with close
        file = nil
      end
    end
  end

  # Store the password and salt in libkv
  #
  # * Stores valid password info in libkv when not already present
  #   * does not overwrite in order to preserve the initial password timestamp
  # * Removes legacy files and returns without a libkv store when it encounters
  #   the following error conditions:
  #   * the password is empty
  #   * only the salt file exists.
  # * Fixes the following error condition and then executes a libkv store
  #   * the existing salt is empty or salt file is missing
  #
  # @raise Exception if the libkv store operation fails
  def migrate_old_file_pair(password_file, salt_file, password_key,
      options, libkv_options)

    remove_bad_files = false
    password = nil
    salt = nil
    if File.exist?(password_file)
      password = IO.readlines(password_file)[0].to_s.chomp
      if password.empty?
        # only store if valid password file exists
        remove_bad_files = true
      else
        salt = get_legacy_salt(salt_file, options)
      end
    else
      # only store if password file exists
      remove_bad_files = true
    end

    if remove_bad_files
      File.unlink(password_file) if File.exist?(password_file)
      File.unlink(salt_file) if File.exist?(salt_file)
    else
      store_password_changes(password, salt, options, password_key,
        libkv_options)
    end
  end

  # @return [password, salt] retrieved from the key/value store
  def retrieve_password_info(password_key, libkv_options)
    key_info = call_function('libkv::get', password_key, libkv_options)['value']
    password = key_info['password']
    salt = key_info['salt']

    [password, salt]
  end

  # store changed password info
  #
  # When existing password+salt in libkv is different than requested password
  # and salt, stores the password and its salt in the key/value store along with
  # metadata containing the password's complexity and complex_only settings
  #
  def store_password_changes(password, salt, options, password_key,
    libkv_options)

    store_required = false
    if call_function('libkv::exists', password_key, libkv_options)
      stored_password, stored_salt = retrieve_password_info(password_key,
        libkv_options)
      if (stored_password != password) || (stored_salt != salt)
        store_required = true
      end
    else
      store_required = true
    end

    if store_required
      store_password_info(password, salt, options, password_key, libkv_options)
    end
  end

  # store a password and its salt in the key/value store along with
  # metadata containing the password's complexity and complex_only settings
  def store_password_info(password, salt, options, password_key, libkv_options)
    key_info = { 'password' => password, 'salt' => salt }
    metadata = {
      'complexity'   => options['complexity'],
      'complex_only' => options['complex_only']
    }

    call_function('libkv::put', password_key, key_info, metadata, libkv_options)
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

end
