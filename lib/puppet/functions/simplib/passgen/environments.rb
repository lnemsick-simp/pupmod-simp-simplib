# Return a list of environments that contain passwords generated and maintained
# by `simplib::passgen`.
#
# Returned list includes any legacy and/or libkv environments found.
# The libkv backend for to which this function will apply is specified
# by the merge of the `libkv_options` parameter and `libkv::options` hieradata.
#
Puppet::Functions.create_function(:'simplib::passgen::environments') do

  # @param type Specifies `simplib::passgen` implementations for which
  #   environments will be listed
  #     * Defaults to 'all'
  #
  # @param libkv
  #   libkv configuration when in libkv mode.
  #
  #     * Will be merged with `libkv::options`.
  #     * All keys are optional.
  #
  # @return [Array[String]] list of environments for which simplib::passgen
  #   passwords exist
  dispatch :environments do
    optional_param "Enum['all','libkv_only','legacy_only']", :type
    optional_param 'Hash',                                   :libkv_options
  end

#FIXME only do what simplib::passgen::libkv tells you
#will be using one or the other exclusively for an environment
  def environments(type = 'all', libkv_options = { 'app_id' => 'simplib::passgen'} )
    environments = []
    if (type == 'all') or (type == 'legacy_only')
      environments << call_function('simplib::legacy::environments')
    end

    if (type == 'all') or (type == 'libkv_only')
      environments << call_function('simplib::libkv::environments', libkv_options)
    end

    environments.flatten.sort.uniq
  end
end

