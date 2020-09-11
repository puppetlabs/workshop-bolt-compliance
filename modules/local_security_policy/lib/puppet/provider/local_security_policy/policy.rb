# frozen_string_literal: true

require 'fileutils'
require 'puppet/util'

begin
  require 'puppet_x/twp/inifile'
  require 'puppet_x/lsp/security_policy'
rescue LoadError => _detail
  require 'pathname' # JJM WORK_AROUND #14073
  module_base = Pathname.new(__FILE__).dirname
  require module_base + '../../../' + 'puppet_x/twp/inifile.rb'
  require module_base + '../../../' + 'puppet_x/lsp/security_policy.rb'
end

Puppet::Type.type(:local_security_policy).provide(:policy) do
  desc 'Puppet type that models the local security policy'

  # TODO: Finalize the registry key settings
  # TODO: Add in registry value translation (ex: 1=enable 0=disable)
  # TODO: Implement self.post_resource_eval (need to collect all resource updates the run secedit to make one call)
  # limit access to windows hosts only
  confine    osfamily: :windows
  defaultfor osfamily: :windows
  # limit access to systems with these commands since this is the tools we need
  commands secedit: 'secedit', reg: 'reg'
  mk_resource_methods

  # exports the current list of policies into a file and then parses that file into
  # provider instances.  If an item is found on the system but not in the lsp_mapping,
  # that policy is not supported only because we cannot match the description
  # furthermore, if a policy is in the mapping but not in the system we would consider
  # that resource absent
  def self.instances
    settings = []
    inf = SecurityPolicy.read_policy_settings
    # need to find the policy, section_header, policy_setting, policy_value and reg_type
    inf.each do |section, parameter_name, parameter_value|
      next if section == 'Unicode'
      next if section == 'Version'
      begin
        policy_desc, policy_values = SecurityPolicy.find_mapping_from_policy_name(parameter_name)

        unless policy_desc.nil?
          policy_hash = {
            name: policy_desc,
            policy_type: section,
            policy_setting: parameter_name,
            policy_default: policy_values[:policy_default],
            policy_value: SecurityPolicy.translate_value(parameter_value, policy_values),
            data_type: policy_values[:data_type],
            reg_type: policy_values[:reg_type],
          }

          # If a policy is in the mapping but not in the system we would consider that
          # resource absent. If a policy is set to the default then we would also consider that
          # resource to be absent. For all other values we would consider it to be present

          ensure_value = if parameter_value.nil?
                           :absent
                         elsif policy_hash[:policy_type] == 'Event Audit'
                           (policy_hash[:policy_value] == policy_hash[:policy_default]) ? :absent : :present
                         else
                           :present
                         end
          policy_hash[:ensure] = ensure_value
          inst = new(policy_hash)
          settings << inst
        end
      rescue KeyError => e
        Puppet.debug e.message
      end
    end
    settings
  end

  # the flush method will be the last method called after applying all the other
  # properties, by default nothing will be enabled or disabled unless the disable/enable are set to true
  # if we ever move to a point were we can write all the settings via one big config file we
  # would want to do that here.
  def flush
    begin
      if @property_hash[:ensure] == :absent && @property_hash[:policy_type] == 'Registry Values' && @property_hash[:policy_default] != 'enabled'
        # The registry key has been removed so no futher action is required
      else
        write_policy_to_system(resource.to_hash)
      end
    rescue KeyError => e
      Puppet.debug e.message
      # send helpful debug message to user here
    end
    @property_hash = resource.to_hash
  end

  def initialize(value = {})
    super(value)
    @property_flush = {}
  end

  # create the resource and convert any user supplied values to computer terms
  def create
    # do everything in flush method
  end

  # this is currently not implemented correctly on purpose until we can figure out how to safely remove
  def destroy
    case @property_hash[:policy_type]
    when 'Registry Values'
      @property_hash[:ensure] = :absent
      if @property_hash[:policy_default] != 'enabled' # sometimes absent can mean that the default value should be 'enabled'
        # deletes the registry key when the policy is absent and the default value is not 'enabled'
        registry_key = 'HKEY_LOCAL_' + @property_hash[:policy_setting].split('\\')[0...-1].join('\\')
        registry_value = @property_hash[:policy_setting].split('\\').last
        reg(['delete', registry_key, '/v', registry_value, '/f'])
      end
      if @property_hash[:policy_default]
        resource[:policy_value] = @property_hash[:policy_default]
      end
    when 'Event Audit'
      @property_hash[:ensure] = :absent
      # reset the Event audit value back to the default when policy is absent
      resource[:policy_value] = @property_hash[:policy_default]
    end
    # other policy values can not be absent.
  end

  def self.prefetch(resources)
    policies = instances
    resources.keys.each do |name|
      if (found_pol = policies.find { |pol| pol.name == name })
        resources[name].provider = found_pol
      end
    end
  end

  def exists?
    @property_hash[:ensure] == :present
  end

  # gets the property hash from the provider
  def to_hash
    instance_variable_get('@property_hash')
  end

  # required for easier mocking, this could be a Tempfile too
  def self.temp_file
    'c:\windows\temp\secedit.inf'
  end

  def temp_file
    'c:\windows\temp\secedit.inf'
  end

  # converts any values that might be of a certain type specified in the mapping
  # converts everything to a string
  # returns the value
  def convert_value(policy_hash)
    case policy_hash[:data_type]
    when :boolean
      value = (policy_hash[:policy_value] == 'enabled') ? '1' : '0'
    when :multi_select
      policy_options = SecurityPolicy.find_mapping_from_policy_desc(policy_hash[:name])[:policy_options]
      policy_options.each { |k, v| policy_options[k] = v.downcase }
      value = policy_options.key(policy_hash[:policy_value].downcase)
    when :string
      value = "\"#{policy_hash[:policy_value]}\""
    else
      value = policy_hash[:policy_value]
    end
    case policy_hash[:policy_type]
    when 'Registry Values'
      value = "#{policy_hash[:reg_type]},#{value}"
    when 'Event Audit'
      value = SecurityPolicy.event_to_audit_id(policy_hash[:policy_value])
    when 'Privilege Rights'
      sids = Array[]
      pv = policy_hash[:policy_value]
      pv.split(',').sort.each do |suser|
        sids << ((suser !~ %r{^(\*S-1-.+)$}) ? ('*' + Puppet::Util::Windows::SID.name_to_sid(suser).to_s) : suser.to_s)
      end
      value = sids.sort.join(',')
    end
    value
  end

  # writes out one policy at a time using the InfFile Class and secedit
  def write_policy_to_system(policy_hash)
    time = Time.now
    time = time.strftime('%Y%m%d%H%M%S')
    infout = "c:\\windows\\temp\\infimport-#{time}.inf"
    sdbout = "c:\\windows\\temp\\sdbimport-#{time}.inf"
    logout = "c:\\windows\\temp\\logout-#{time}.inf"
    _status = nil
    begin
      # read the system state into the inifile object for easy variable setting
      inf = PuppetX::IniFile.new
      # these sections need to be here by default
      inf['Version'] = { 'signature' => '$CHICAGO$', 'Revision' => 1 }
      inf['Unicode'] = { 'Unicode' => 'yes' }
      section = policy_hash[:policy_type]
      section_value = { policy_hash[:policy_setting] => convert_value(policy_hash) }
      # we can utilize the IniFile class to write out the data in ini format
      inf[section] = section_value
      inf.write(filename: infout, encoding: 'utf-8')
      secedit('/configure', '/db', sdbout, '/cfg', infout)
    ensure
      FileUtils.rm_f(temp_file)
      FileUtils.rm_f(infout)
      FileUtils.rm_f(sdbout)
      FileUtils.rm_f(logout)
    end
  end
end
