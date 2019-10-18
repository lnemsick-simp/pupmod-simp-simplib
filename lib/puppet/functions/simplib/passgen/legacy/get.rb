# Retrieves a generated password and any stored attributes that have
# been stored on a on local file system at
# `Puppet.settings[:vardir]/simp/environments/$environment/simp_autofiles/gen_passwd/`
#
# Terminates catalog compilation if the password storage directory
# cannot be accessed by the user.
Puppet::Functions.create_function(:'simplib::passgen::legacy::get') do

  # @param identifier Unique `String` to identify the password usage.
  #   Must conform to the following:
  #   * Identifier must contain only the following characters:
  #     * a-z
  #     * A-Z
  #     * 0-9
  #     * The following special characters:  `._:-`
  #
  # @return [Hash] Password information or {} if the password does not exist
  #
  #   * 'value'- Hash containing 'password' and 'salt' attributes
  #   * 'metadata' - Hash containing 'complexity' and 'complex_only' attributes
  #     when that information is available; {} otherwise.
  #
  # @raise Exception if a legacy password file is inaccessible by the user
  #
  dispatch :get do
    required_param 'String[1]', :identifier
  end

  def get(identifier)
    keydir = File.join(Puppet.settings[:vardir], 'simp', 'environments',
      scope.lookupvar('::environment'), 'simp_autofiles', 'gen_passwd')

    password_info = { 'value' => {}, 'metadata' => {} }

    # retrieve password
    password_file = File.join(keydir, identifier)
    if File.exist?(password_file)
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
    end

    password_info
  end
end


  def get_current_password(identifier, options, settings)
    # Open the file in append + read mode to prepare for what is to
    # come.
    tgt = File.new("#{settings['keydir']}/#{identifier}","a+")
    tgt_hash = File.new("#{tgt.path}.salt","a+")

    # These chowns are applicable as long as they are applied
    # by puppet, not puppetserver.
    FileUtils.chown(settings['user'],settings['group'],tgt.path)
    FileUtils.chown(settings['user'],settings['group'],tgt_hash.path)

    passwd = ''
    salt = ''

    # Create salt file if not there, no matter what, just in case we have an
    # upgraded system.
    if tgt_hash.stat.size.zero?
      if options.key?('salt')
        salt = options['salt']
      else
        salt = gen_salt(options)
      end
      tgt_hash.puts(salt)
      tgt_hash.rewind
    end

    if tgt.stat.size.zero?
      if options.key?('password')
        passwd = options['password']
      else
        passwd = gen_password(options)
      end
      tgt.puts(passwd)
    else
      passwd = tgt.gets.chomp
      salt = tgt_hash.gets.chomp

      if !options['return_current'] and passwd.length != options['length']
        tgt_last = File.new("#{tgt.path}.last","w+")
        tgt_last.puts(passwd)
        tgt_last.chmod(0640)
        tgt_last.flush
        tgt_last.close

        tgt_hash_last = File.new("#{tgt_hash.path}.last","w+")
        tgt_hash_last.puts(salt)
        tgt_hash_last.chmod(0640)
        tgt_hash_last.flush
        tgt_hash_last.close

        tgt.rewind
        tgt.truncate(0)
        passwd = gen_password(options)
        salt = gen_salt(options)

        tgt.puts(passwd)
        tgt_hash.puts(salt)
      end
    end

    tgt.chmod(0640)
    tgt.flush
    tgt.close

    [passwd, salt]
  end

  # Try to get the last password entry, if it exists.  If it doesn't
  # use the current entry, the 'password' in options, or a freshly-
  # generated password, in that order of precedence.  Also, warn the
  # user about manifest ordering problems, if we had to use the
  # 'password' in options or had to generate a password.
  def get_last_password(identifier, options, settings)
    toread = nil
    if File.exists?("#{settings['keydir']}/#{identifier}.last")
      toread = "#{settings['keydir']}/#{identifier}.last"
    else
      toread = "#{settings['keydir']}/#{identifier}"
    end

    passwd = ''
    salt = ''
    if File.exists?(toread)
      passwd = IO.readlines(toread)[0].to_s.chomp
      sf = "#{File.dirname(toread)}/#{File.basename(toread,'.last')}.salt.last"
      saltfile = File.open(sf,'a+',0640)
      if saltfile.stat.size.zero?
        if options.key?('salt')
          salt = options['salt']
        else
          salt = gen_salt(options)
        end
        saltfile.puts(salt)
        saltfile.close
      end
      salt = IO.readlines(sf)[0].to_s.chomp
    else
      warn_msg = "Could not find a primary or 'last' file for " +
        "#{identifier}, please ensure that you have included this" +
        " function in the proper order in your manifest!"
      Puppet.warning warn_msg
      if options.key?('password')
        passwd = options['password']
      else
        #FIXME?  Why doesn't this persist the password?
        passwd = gen_password(options)
      end
    end
    [passwd, salt]
  end

  # Ensure that the password space is readable and writable by the
  # Puppet user and no other users.
  # Fails if any file/directory not owned by the Puppet user is found.
  def lockdown_stored_password_perms(settings)
    unowned_files = []
    Find.find(settings['keydir']) do |file|
      file_stat = File.stat(file)

      # Do we own this file?
      begin
        file_owner = Etc.getpwuid(file_stat.uid).name

        unowned_files << file unless (file_owner == settings['user'])
      rescue ArgumentError => e
        debug("simplib::passgen: Error getting UID for #{file}: #{e}")

        unowned_files << file
      end

      # Ignore any file/directory that we don't own
      Find.prune if unowned_files.last == file

      FileUtils.chown(settings['user'],
        settings['group'], file
      )

      file_mode = file_stat.mode
      desired_mode = symbolic_mode_to_int('u+rwX,g+rX,o-rwx',file_mode,File.directory?(file))

      unless (file_mode & 007777) == desired_mode
        FileUtils.chmod(desired_mode,file)
      end
    end

    unless unowned_files.empty?
      err_msg = <<-EOM.gsub(/^\s+/,'')
        simplib::passgen: Error: Could not verify ownership by '#{settings['user']}' on the following files:
        * #{unowned_files.join("\n* ")}
      EOM

      fail(err_msg)
    end
  end
end
# vim: set expandtab ts=2 sw=2:
