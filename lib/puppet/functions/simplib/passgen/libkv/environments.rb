# Return a list of environments that contain passwords generated and maintained by
# libkv-enabled `simplib::passgen`.
#
Puppet::Functions.create_function(:'simplib::passgen::libkv::environments') do

  # @param libkv
  #   libkv configuration when in libkv mode.
  #
  #     * Will be merged with `libkv::options`.
  #     * All keys are optional.
  #
  # @return [Array[String]] list of environments for which simplib::passgen
  #   passwords exist
  dispatch :environments do
    optional_param 'Hash', :libkv_options
  end

  def environments(libkv_options = { 'app_id' => 'simplib::passgen'} )
    # retrieve list of all environments for libkv backend for this application
    options = libkv_options.dup
    options['environment'] = ''
    options['softfail'] = true
    environments = libkv::list('/', options)['folders']
    return [] if environments.nil?

    # remove any passgen environments that do not have key files
    environments.delete_if do |env|
      # FIXME: For now, only looking a top-level gen_passwd directory.  This
      # is because legacy simplib::passgen did not handle keys with '/' in them.
      options['environment'] = env
      result = libkv::list('gen_passwd', options)
      result.nil? or result['keys'].empty?
    end

    environments
  end

end
