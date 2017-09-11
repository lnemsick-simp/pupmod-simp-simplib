#  Transforms an input string to one or more interval values for `cron`.
#  This can be used to avoid starting a certain cron job at the same
#  time on all servers.

Puppet::Functions.create_function(:'simplib::rand_cron') do

  local_types do
    type "RandCronAlgorithm = Enum['crc32', 'ip_mod', 'sha256']"
  end

  # @param modifier
  #   The input string to use as the basis for the generated values.
  #
  # @param algorithm
  #   Randomization algorithm to apply to transform the input string.
  #
  #   When 'sha256' and the input string is not an IP address, a random
  #   number generated from the input string via sha256 is used as the
  #   basis for the returned values.
  #
  #   When 'sha256' and the input string is an IP address, a random
  #   number generated from the numeric IP via sh256 is used as the
  #   basis for the returned values.  This algorithm works well to
  #   create cron job intervals for multiple hosts, when the number
  #   of hosts is less than the `max_value` or the hosts do not have
  #   linearly-assigned IP addresses.
  #
  #   When 'ip_mod' and the input string is an IP address, the modulus
  #   of the numeric IP is used as the basis for the returned values.
  #   This algorithm works well to create cron job intervals for
  #   multiple hosts, when the number of hosts exceeds the `max_value`
  #   and the hosts have linearly-assigned IP addresses.
  #
  #   When 'crc32', the crc32 of the input string will be used as the
  #   basis for the returned values.
  #
  # @param occurs
  #   The occurrence within an interval, i.e., the number of values to
  #   be generated for the interval. Defaults to `1`.
  #
  # @param max_value
  #   The maximum value for the interval.  The values generated will
  #   be in the inclusive range [0, max_value]. Defaults to `60` for
  #   use in the `minute` cron field.
  #
  # @return [Array[Integer]] Array of integers suitable for use in the
  #   ``minute`` or ``hour`` cron field.
  #
  # @example Generate one value for the `minute` cron interval using
  #   the 'sha256' algorithm
  #
  #   rand_cron('sha256','myhost.test.local')
  #
  # @example Generate 2 values for the `minute` cron interval using
  #   the 'sha256' algorithm applied to the numeric representation of
  #   an IP
  #
  #   rand_cron('sha256','10.0.23.45')
  #
  # @example Generate 2 values for the `hour` cron interval, using the
  #   'ip_mod' algorithm
  #
  #   rand_cron('ip_mod', '10.0.6.78', 2, 23)
  #
  dispatch :rand_cron do
    required_param 'String',            :modifier
    required_param 'RandCronAlgorithm', :algorithm
    optional_param 'Integer[1]',        :occurs
    optional_param 'Integer[1]',        :max_value
  end

  # +param+: modifier Input string to be transformed to an Integer
  # +param+: algorithm Algorithm to apply to transform input string into
  #   an Integer
  #
  # +return+: Integer to be used as a basis for generated cron values
  def generate_numeric_modifier(modifier, algorithm)
    range_modifier = nil
    if algorithm == 'crc32'
      require 'zlib'
      range_modifier = Zlib.crc32(modifier)
    else  # 'sha256' or 'ip_mod'
      require 'ipaddr'
      require 'digest'

      ip_num = nil
      begin
        ip_num = IPAddr.new(modifier).to_i
      rescue IPAddr::Error
      end

      if ip_num.nil?
        if algorithm == 'ip_mod'
          fail("simplib::rand_cron: '#{modifier}' is not a valid IP address")
        else
          range_modifier = Digest::SHA256.hexdigest(modifier).hex
        end
      else
        if algorithm == 'ip_mod'
          range_modifier = ip_num
        else
          range_modifier = Digest::SHA256.hexdigest(ip_num.to_s).hex
        end
      end
    end
    range_modifier
  end

  def rand_cron(modifier, algorithm, occurs = 1, max_value = 59)
    range_modifier = generate_numeric_modifier(modifier, algorithm)
    modulus = max_value + 1
    base = range_modifier % modulus

    values = []
    if occurs == 1
      values << base
    else
      values = Array.new
      (1..occurs).each do |i|
        values << ((base - (modulus / occurs * i)) % modulus)
      end
    end
    return values.sort
  end
end
