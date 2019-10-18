# Sets a generated password with attributes, optionally backing up
# existing information for the password
#
# * Backed up password has an identifier `<identifier>.last`
# * Supports 2 modes:
#   * libkv
#     * Password info is stored in a key/value store and stored using libkv.
#     * Terminates catalog compilation if any libkv operation fails.
#   * Legacy
#     * Password info is stored in files on the local file system at
#       `Puppet.settings[:vardir]/simp/environments/$environment/simp_autofiles/gen_passwd/`.
#     * Terminates catalog compilation if any password files cannot be
#       be created/modified by the user.
# * To enable libkv implementation, set `simplib::passgen::libkv` to `true`
#   in hieradata. When that setting absent or false, legacy mode will be used.
#
Puppet::Functions.create_function(:'simplib::passgen::set') do

  # @param identifier Unique `String` to identify the password usage.
  #   Must conform to the following:
  #   * Identifier must contain only the following characters:
  #     * a-z
  #     * A-Z
  #     * 0-9
  #     * The following special characters:
  #       * `._:-` for the legacy implementation
  #       * `._:-/` for the libkv-enabled implementation
  #   * Identifier may not contain '/./' or '/../' sequences.
  #
  # @param password Password value
  # @param salt Salt for the password for use in encryption operations
  # @param password_options
  #   Other password attributes that would be required to regenerate the
  #   password with standlone use of `simplib::passgen`.  Not applicable
  #   to legacy mode.
  #
  # @option password_options [Integer[0,2]] 'complexity'
  #   Specifies the types of characters to be used in the password
  #     * `0` => Default. Use only Alphanumeric characters in your password (safest)
  #     * `1` => Add reasonably safe symbols
  #     * `2` => Printable ASCII
  # @option password_options [Boolean] 'complex_only'
  #   Whether to use only the characters explicitly added by the complexity rules.
  #   For example, when `complexity` is `1`, create a password from only safe symbols.
  #   Defaults to `false`.
  #
  # @param backup
  #   Whether to backup the existing password information with
  #   an identifier of `<identifier>`.last
  #
  # @param libkv_options
  #   libkv configuration when in libkv mode.
  #
  #     * Will be merged with `libkv::options`.
  #     * All keys are optional.
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
  # @raise Exception if a libkv operation fails, or any legacy password files
  #   cannot be be created/modified by the user.
  #
  dispatch :set do
    required_param 'String[1]', :identifier
    required_param 'String[1]', :password
    required_param 'String[1]', :salt
    optional_param 'Hash',      :password_options
    optional_param 'Boolean',   :backup
    optional_param 'Hash',      :libkv_options
  end

  def set(identifier, password, salt, password_options={}, backup=true,
      libkv_options={'app_id' => 'simplib::passgen'})

    use_libkv = call_function('lookup', 'simplib::passgen::libkv',
      { 'default_value' => false })

    password = nil
    if use_libkv
      password = call_function('simplib::passgen::libkv::set', identifier,
        password, salt, password_options, backup, libkv_options)
    else
      password = call_function('simplib::passgen::legacy::set', identifier,
        password, salt, backup)
    end
  end
end
