# Retrieves a generated password and any stored attributes from a
# key/value store using libkv
#
# Terminates catalog compilation if any libkv operation fails.
#
Puppet::Functions.create_function(:'simplib::passgen::libkv::get') do

  # @param identifier Unique `String` to identify the password usage.
  #   Must conform to the following:
  #   * Identifier must contain only the following characters:
  #     * a-z
  #     * A-Z
  #     * 0-9
  #     * The following special characters: `._:-/`
  #   * Identifier may not contain '/./' or '/../' sequences.
  #
  # @param libkv_options
  #   libkv configuration that will be merged `libkv::options`.
  #   All keys are optional.
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
  # @return [Hash] Password information or {} if the password does not exist
  #
  #   * 'value'- Hash containing 'password' and 'salt' attributes
  #   * 'metadata' - Hash containing 'complexity' and 'complex_only' attributes
  #     when that information is available; {} otherwise.
  #
  # @raise Exception if a libkv operation fails
  #
  dispatch :get do
    required_param 'String[1]', :identifier
    optional_param 'Hash',      :libkv_options
  end

  def get(identifier, libkv_options={'app_id' => 'simplib::passgen'})
    key_root_dir = call_function('simplib::passgen::libkv::root_dir')
    key = "#{key_root_dir}/#{identifier}"
    password_info = {}
    if call_function('libkv::exists', key, libkv_options)
      password_info = call_function('libkv::get', key, libkv_options)
    end
    password_info
  end
end
