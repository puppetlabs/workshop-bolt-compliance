# frozen_string_literal: true

begin
  require 'puppet_x/lsp/security_policy'
rescue LoadError => _detail
  require 'pathname' # JJM WORK_AROUND #14073
  module_base = Pathname.new(__FILE__).dirname
  require module_base + '../../' + 'puppet_x/lsp/security_policy.rb'
end

Puppet::Type.newtype(:local_security_policy) do
  @doc = 'Puppet type that models the local security policy'

  ensurable

  newparam(:name, namevar: true) do
    desc 'Local Security Setting Name. What you see it the GUI.'
    validate do |value|
      raise ArgumentError, "Invalid Policy name: #{value}" unless SecurityPolicy.valid_lsp?(value)
    end
  end

  newproperty(:policy_type) do
    newvalues('System Access', 'Event Audit', 'Privilege Rights', 'Registry Values', nil, '')
    desc 'Local Security Policy Machine Name.  What OS knows it by.'
    defaultto do
      begin
        policy_hash = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
      rescue KeyError => e
        raise(e.message)
      end
      policy_hash[:policy_type]
    end
    # uses the resource name to perform a lookup of the defined policy and returns the policy type
    munge do |_value|
      begin
        policy_hash = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
      rescue KeyError => e
        raise(e.message)
      end
      policy_hash[:policy_type]
    end
  end

  newproperty(:policy_setting) do
    desc 'Local Security Policy Machine Name.  What OS knows it by.'
    defaultto do
      begin
        policy_hash = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
      rescue KeyError => e
        raise(e.message)
      end
      policy_hash[:name]
    end
    munge do |_value|
      begin
        policy_hash = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
      rescue KeyError => e
        raise(e.message)
      end
      policy_hash[:name]
    end
  end

  newproperty(:policy_value) do
    desc 'Local Security Policy Setting Value'
    validate do |value|
      SecurityPolicy.validate_policy_value(resource.to_hash, value)
    end
    munge do |value|
      SecurityPolicy.convert_policy_value(resource.to_hash, value, SecurityPolicy.get_policy_value_current(resource[:name]))
    end
  end

  newproperty(:policy_default) do
    desc 'Local Security Policy Setting Value'
    validate do |value|
      SecurityPolicy.validate_policy_default(resource.to_hash, value)
    end
    munge do |value|
      SecurityPolicy.convert_policy_default(resource.to_hash, value)
    end
  end

  newproperty(:data_type) do
    desc 'Local Security Policy data type.'
    defaultto do
      begin
        policy_hash = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
      rescue KeyError => e
        raise(e.message)
      end
      policy_hash[:data_type]
    end
  end

  newproperty(:reg_type) do
    desc 'Local Security Policy reg type.'
    defaultto do
      begin
        policy_hash = SecurityPolicy.find_mapping_from_policy_desc(resource[:name])
      rescue KeyError => e
        raise(e.message)
      end
      policy_hash[:reg_type]
    end
  end
end
