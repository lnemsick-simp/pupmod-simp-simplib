# Retrieves the list of generated passwords with attributes stored
# in files on the local files system at
# `Puppet.settings[:vardir]/simp/environments/$environment/simp_autofiles/gen_passwd/`.
#
# * List will contain the current and previous passwords.
#   * Names of previous passwords will end in '.last'.
# * Terminates catalog compilation if any password file cannot be accessed
#   by the user.
#
Puppet::Functions.create_function(:'simplib::passgen::legacy::list') do

  # @return [Hash]  Hash of results or {} if folder does not exist or cannot
  #   be accessed.
  #
  #   * 'keys' = Hash of password information
  #     * 'value'- Hash containing 'password' and 'salt' attributes
  #     * 'metadata' - Hash containing other stored attributes.  Will always be empty,
  #       as the legacy simplib::passgen does not store any other attributes.
  #   * 'folders' = Array of sub-folder names.  Will always be empty, as legacy
  #     simplib::passgen does not support password identifiers prefixed with a
  #     folder path
  #
  # @raise Exception If any password file cannot be accessed by the user.
  #
  dispatch :passgen do
    optional_param 'String', :folder
    optional_param 'Hash',   :libkv_options
  end

  def list
    keydir = File.join(Puppet.settings[:vardir], 'simp', 'environments',
      scope.lookupvar('::environment'), 'simp_autofiles', 'gen_passwd')

    results = {}
    if Dir.exist?(keydir)
      Dir.chdir(keydir) do
        names = Dir.glob('*').delete_if do |name|
          # Exclude sub-directories (which legacy simplib::passgen doesn't
          # create) and salt file
          File.directory?(name) || !(name =~ /\.salt(\.last)?$/).nil?
        end

        results['folders'] = []
        results['keys'] = {}
        names.each do |name|
          password_info = { 'value' => {}, 'metadata' => {} }
          password = IO.readlines(password_file)[0].to_s.chomp
          password_info['value']['password'] = password

          # retrieve salt
          salt_file = "#{password_file}.salt"
          if password_file =~ /\.last$/
            salt_file = "#{password_file.gsub('.last','')}.salt.last"
          end

          if File.exist?(salt_file)
            salt = IO.readlines(salt_file)[0].to_s.chomp
            password_info['value']['salt'] = salt
          else
            password_info['value']['salt'] = ''
          end

          results['keys'][name] = password_info
        end
      end
    end

    if results.key?('keys') && results['keys'].empty?
      results = {}
    end

    results
  end
end

