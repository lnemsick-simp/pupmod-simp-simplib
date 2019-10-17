# Return a list of environments that contain passwords generated and maintained by
# legacy `simplib::passgen`.
#
Puppet::Functions.create_function(:'simplib::passgen::legacy::environments') do

  # @return [Array[String]] list of environments for which simplib::passgen
  #   passwords exist
  dispatch :environments do
  end

  def environments
    keydir = File.join(Puppet.settings[:vardir], 'simp', 'environments')
    env_dirs = Dir.glob(File.join(keydir, '*'))

    # remove any passgen env dirs that do not have key files
    env_dirs.delete_if do |env|
      entries = Dir.glob(File.join(env, 'simp_autofiles', 'gen_passwd','*'))
      # exclude subdirectories (which must have been manually created)
      # and salt files
      entries.delete_if do |entry|
        File.directory?(entry) or !(entry =~ /\.salt(\.last)?$/).nil?
      end
      entries.empty?
    end

    env_dirs.map { |dir| File.basename(dir) }
  end

end
