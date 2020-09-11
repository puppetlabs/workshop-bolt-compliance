# frozen_string_literal: true

require 'puppet/provider'
require 'puppet/util'

# class SecurityPolicy
class SecurityPolicy
  EVENT_TYPES = ['Success,Failure', 'Success', 'Failure', 'No auditing']
  STATE_TYPES = %w[enabled disabled]

  def user_to_sid(value)
    '*' + Puppet::Util::Windows::SID.name_to_sid(value)
  end

  def convert_privilege_right(policy_hash, policy_value, policy_value_current)
    # we need to convert users to sids first
    policy_value_new = policy_value_current.split(',').sort
    if policy_hash[:ensure].to_s == 'absent'
      pv = ''
    else
      if policy_value.include? ':'
        pvm = policy_value.split(':')[1]
        task = policy_value.split(':')[0]
      else
        pvm = policy_value
        task = 'set:'
      end

      if task == 'merge'
        pvm.split(',').sort.each do |muser|
          muser.strip!
          # rubocop:disable Performance/RegexpMatch
          # needed when using ruby 2.1
          if muser =~ %r{^\-}
            policy_value_new.delete(user_to_sid(muser.delete('-')))
          else
            policy_value_new.push(user_to_sid(muser.delete('+')))
          end
          # rubocop:enable Performance/RegexpMatch
        end
      else
        pvm.split(',').sort.each do |suser|
          policy_value_new << user_to_sid(suser)
        end
      end

      pv = policy_value_new.uniq.sort.join(',')
    end
    pv
  end

  def self.get_policy_value_current(policy_name)
    policy_value_current = 'empty?'
    inf = read_policy_settings
    # need to find the policy, section_header, policy_setting, policy_value and reg_type
    inf.each do |section, parameter_name, parameter_value|
      next if section == 'Unicode'
      next if section == 'Version'
      begin
        policy_desc, policy_values = SecurityPolicy.find_mapping_from_policy_name(parameter_name)
        if policy_desc == policy_name
          policy_value_current = translate_value(parameter_value, policy_values)
        end
      rescue KeyError => e
        Puppet.debug e.message
      end
    end
    policy_value_current
  end

  # export and then read the policy settings from a file into a inifile object
  # caches the IniFile object during the puppet run
  def self.read_policy_settings(inffile = nil)
    inffile ||= temp_file
    unless @file_object
      export_policy_settings(inffile)
      File.open inffile, 'r:IBM437' do |file|
        # remove /r/n and remove the BOM
        inffile_content = file.read.force_encoding('utf-16le').encode('utf-8', universal_newline: true).delete("\xEF\xBB\xBF")
        @file_object ||= PuppetX::IniFile.new(content: inffile_content)
      end
    end
    @file_object
  end

  def self.temp_file
    'c:\windows\temp\secedit.inf'
  end

  # export the policy settings to the specified file and return the filename
  def self.export_policy_settings(inffile = nil)
    inffile ||= temp_file
    system("cmd /c c:/windows/system32/secedit.exe /export /cfg #{temp_file} >nil")
    inffile
  end

  # converts any values that might be of a certain type specified in the mapping
  # converts everything to a string
  # returns the value
  def self.translate_value(value, policy_values)
    value = value.to_s.strip
    case policy_values[:policy_type]
    when 'Registry Values'
      value = return_actual_policy_value(value, policy_values[:reg_type])
    when 'Event Audit'
      value = SecurityPolicy.event_audit_mapper(value)
    when 'Privilege Rights'
      sids = Array.[]
      value.split(',').sort.each do |suser|
        sids << ((suser !~ %r{^(\*S-1-.+)$}) ? ('*' + Puppet::Util::Windows::SID.name_to_sid(suser).to_s) : suser.to_s)
      end
      value = sids.sort.join(',')
    end
    case policy_values[:data_type]
    when :boolean
      value = value.to_i.zero? ? 'disabled' : 'enabled'
    when :multi_select
      value = policy_values[:policy_options][value]
    end
    value
  end

  def self.return_actual_policy_value(value, reg_type)
    value = (reg_type == '1') ? value.delete('"').split(',').drop(1).join(',') : value.split(',').drop(1).join(',')
    value
  end

  # Converts a event number to a word
  def self.event_audit_mapper(policy_value)
    case policy_value.to_s
    when '3'
      'Success,Failure'
    when '2'
      'Failure'
    when '1'
      'Success'
    else
      'No auditing'
    end
  end

  # Converts a event number to a word
  def self.event_to_audit_id(event_audit_name)
    case event_audit_name
    when 'Success,Failure'
      '3'
    when 'Failure'
      '2'
    when 'Success'
      '1'
    when 'No auditing'
      '0'
    else
      event_audit_name
    end
  end

  # returns the key and hash value given the policy name
  def self.find_mapping_from_policy_name(name)
    key, value = lsp_mapping.find do |_key, hash|
      hash[:name] == name
    end
    [key, value]
  end

  # returns the key and hash value given the policy desc
  def self.find_mapping_from_policy_desc(desc)
    name = desc.downcase
    _key, value = lsp_mapping.find do |key, _hash|
      key.downcase == name
    end
    unless value
      raise KeyError, "#{desc} is not a valid policy"
    end
    value
  end

  def self.valid_lsp?(name)
    lsp_mapping.keys.include?(name)
  end

  def self.convert_registry_value(name, value)
    value = value.to_s
    return value if value.split(',').count > 1
    policy_hash = find_mapping_from_policy_desc(name)
    "#{policy_hash[:reg_type]},#{value}"
  end

  # converts the policy value to machine values
  def self.convert_policy_value(policy_hash, value, policy_value_current)
    sp = SecurityPolicy.new
    # I would rather not have to look this info up, but the type code will not always have this info handy
    # without knowing the policy type we can't figure out what to convert
    policy_type = find_mapping_from_policy_desc(policy_hash[:name])[:policy_type]
    case policy_type.to_s
    when 'Privilege Rights'
      value = sp.convert_privilege_right(policy_hash, value, policy_value_current)
    end
    value
  end

  # validates the policy value
  def self.validate_policy_value(resource_hash, value)
    _sp = SecurityPolicy.new
    # I would rather not have to look this info up, but the type code will not always have this info handy
    # without knowing the policy type we can't figure out what to convert
    policy_hash = find_mapping_from_policy_desc(resource_hash[:name])
    case policy_hash[:policy_type]
    when 'Event Audit'
      raise ArgumentError, "Invalid policy value: '#{value}' for '#{resource_hash[:name]}', should be one of '#{SecurityPolicy::EVENT_TYPES.join(', ')}'" unless
        SecurityPolicy::EVENT_TYPES.include?(value)
    when 'System Access', 'Registry Values'
      case policy_hash[:data_type]
      when :boolean
        raise ArgumentError, "Invalid policy value: '#{value}' for '#{resource_hash[:name]}', should be one of '#{SecurityPolicy::STATE_TYPES.join(', ')}'" unless
          SecurityPolicy::STATE_TYPES.include?(value)
      when :multi_select
        raise ArgumentError, "Invalid policy value: '#{value}' for '#{resource_hash[:name]}', should be one of '#{policy_hash[:policy_options].values.join(', ')}'" unless
          policy_hash[:policy_options].values.include?(value)
      end
    when 'Privilege Rights'
      if value.include? ':'
        pvm = value.split(':')[1]
        task = value.split(':')[0]
      else
        pvm = value
        task = 'set:'
      end

      unless task == 'merge'
        pvm.split(',').sort.each do |muser|
          muser.strip!
          raise ArgumentError, "Invalid policy value: '#{value}' for '#{resource_hash[:name]}', value may not start with a '-'" if muser =~ %r{^\-}
          raise ArgumentError, "Invalid policy value: '#{value}' for '#{resource_hash[:name]}', value may not start with a '+'" if muser =~ %r{^\+}
        end
      end
    end
  end

  def self.lsp_mapping
    @lsp_mapping ||= {
      # Password policy Mappings
      'Enforce password history' => {
        name:           'PasswordHistorySize',
        policy_type:    'System Access',
        data_type:      :integer,
        policy_default: '0',
      },
      'Maximum password age' => {
        name:           'MaximumPasswordAge',
        policy_type:    'System Access',
        data_type:      :integer,
        policy_default: '42',
      },
      'Minimum password age' => {
        name:           'MinimumPasswordAge',
        policy_type:    'System Access',
        data_type:      :integer,
        policy_default: '0',
      },
      'Minimum password length' => {
        name:           'MinimumPasswordLength',
        policy_type:    'System Access',
        data_type:      :integer,
        policy_default: '0',
      },
      'Password must meet complexity requirements' => {
        name:           'PasswordComplexity',
        policy_type:    'System Access',
        data_type:      :boolean,
        policy_default: 'enabled',
      },
      'Store passwords using reversible encryption' => {
        name:           'ClearTextPassword',
        policy_type:    'System Access',
        data_type:      :boolean,
        policy_default: 'disabled',
      },
      'Account lockout duration' => {
        name:           'LockoutDuration',
        policy_type:    'System Access',
        data_type:      :integer,
        policy_default: '30',
      },
      'Account lockout threshold' => {
        name:           'LockoutBadCount',
        policy_type:    'System Access',
        data_type:      :integer,
        policy_default: '0',
      },
      'Reset account lockout counter after' => {
        name:           'ResetLockoutCount',
        policy_type:    'System Access',
        data_type:      :integer,
        policy_default: '30',
      },
      # Audit Policy Mappings
      'Audit account logon events' => {
        name:           'AuditAccountLogon',
        policy_type:    'Event Audit',
        policy_default: 'No auditing',
      },
      'Audit account management' => {
        name:           'AuditAccountManage',
        policy_type:    'Event Audit',
        policy_default: 'No auditing',
      },
      'Audit directory service access' => {
        name:           'AuditDSAccess',
        policy_type:    'Event Audit',
        policy_default: 'No auditing',
      },
      'Audit logon events' => {
        name:           'AuditLogonEvents',
        policy_type:    'Event Audit',
        policy_default: 'No auditing',
      },
      'Audit object access' => {
        name:           'AuditObjectAccess',
        policy_type:    'Event Audit',
        policy_default: 'No auditing',
      },
      'Audit policy change' => {
        name:           'AuditPolicyChange',
        policy_type:    'Event Audit',
        policy_default: 'No auditing',
      },
      'Audit privilege use' => {
        name:           'AuditPrivilegeUse',
        policy_type:    'Event Audit',
        policy_default: 'No auditing',
      },
      'Audit process tracking' => {
        name:           'AuditProcessTracking',
        policy_type:    'Event Audit',
        policy_default: 'No auditing',
      },
      'Audit system events' => {
        name:           'AuditSystemEvents',
        policy_type:    'Event Audit',
        policy_default: 'No auditing',
      },
      # User rights mapping
      'Access Credential Manager as a trusted caller' => {
        name:           'SeTrustedCredManAccessPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '',
      },
      'Access this computer from the network' => {
        name:           'SeNetworkLogonRight',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551',
      },
      'Act as part of the operating system' => {
        name:           'SeTcbPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '',
      },
      'Add workstations to domain' => {
        name:           'SeMachineAccountPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '',
      },
      'Adjust memory quotas for a process' => {
        name:           'SeIncreaseQuotaPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-19,*S-1-5-20,*S-1-5-32-544',
      },
      'Allow log on locally' => {
        name:           'SeInteractiveLogonRight',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551',
      },
      'Allow log on through Remote Desktop Services' => {
        name:           'SeRemoteInteractiveLogonRight',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544,*S-1-5-32-555',
      },
      'Back up files and directories' => {
        name:           'SeBackupPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544,*S-1-5-32-551',
      },
      'Bypass traverse checking' => {
        name:           'SeChangeNotifyPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-1-0,*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551',
      },
      'Change the system time' => {
        name:           'SeSystemtimePrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-19,*S-1-5-32-544',
      },
      'Change the time zone' => {
        name:           'SeTimeZonePrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-19,*S-1-5-32-544',
      },
      'Create a pagefile' => {
        name:           'SeCreatePagefilePrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544',
      },
      'Create a token object' => {
        name:           'SeCreateTokenPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '',
      },
      'Create global objects' => {
        name:           'SeCreateGlobalPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6',
      },
      'Create permanent shared objects' => {
        name:           'SeCreatePermanentPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '',
      },
      'Create symbolic links' => {
        name:           'SeCreateSymbolicLinkPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544',
      },
      'Debug programs' => {
        name:           'SeDebugPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544',
      },
      'Deny access to this computer from the network' => {
        name:           'SeDenyNetworkLogonRight',
        policy_type:    'Privilege Rights',
        policy_default: '',
      },
      'Deny log on as a batch job' => {
        name:           'SeDenyBatchLogonRight',
        policy_type:    'Privilege Rights',
        policy_default: '',
      },
      'Deny log on as a service' => {
        name:           'SeDenyServiceLogonRight',
        policy_type:    'Privilege Rights',
        policy_default: '',
      },
      'Deny log on locally' => {
        name:           'SeDenyInteractiveLogonRight',
        policy_type:    'Privilege Rights',
        policy_default: '',
      },
      'Deny log on through Remote Desktop Services' => {
        name:           'SeDenyRemoteInteractiveLogonRight',
        policy_type:    'Privilege Rights',
        policy_default: '',
      },
      'Enable computer and user accounts to be trusted for delegation' => {
        name:           'SeEnableDelegationPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '',
      },
      'Force shutdown from a remote system' => {
        name:           'SeRemoteShutdownPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544',
      },
      'Generate security audits' => {
        name:           'SeAuditPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-19,*S-1-5-20',
      },
      'Impersonate a client after authentication' => {
        name:           'SeImpersonatePrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6',
      },
      'Increase a process working set' => {
        name:           'SeIncreaseWorkingSetPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-545',
      },
      'Increase scheduling priority' => {
        name:           'SeIncreaseBasePriorityPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544',
      },
      'Load and unload device drivers' => {
        name:           'SeLoadDriverPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544',
      },
      'Lock pages in memory' => {
        name:           'SeLockMemoryPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '',
      },
      'Log on as a batch job' => {
        name:           'SeBatchLogonRight',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-559',
      },
      'Log on as a service' => {
        name:           'SeServiceLogonRight',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-80-0',
      },
      'Manage auditing and security log' => {
        name:           'SeSecurityPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544',
      },
      'Modify an object label' => {
        name:           'SeRelabelPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '',
      },
      'Modify firmware environment values' => {
        name:           'SeSystemEnvironmentPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544',
      },
      'Perform volume maintenance tasks' => {
        name:           'SeManageVolumePrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544',
      },
      'Profile single process' => {
        name:           'SeProfileSingleProcessPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544',
      },
      'Profile system performance' => {
        name:           'SeSystemProfilePrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420',
      },
      'Remove computer from docking station' => {
        name:           'SeUndockPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544',
      },
      'Replace a process level token' => {
        name:           'SeAssignPrimaryTokenPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-19,*S-1-5-20',
      },
      'Restore files and directories' => {
        name:           'SeRestorePrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544,*S-1-5-32-551',
      },
      'Shut down the system' => {
        name:           'SeShutdownPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544,*S-1-5-32-551',
      },
      'Synchronize directory service data' => {
        name:           'SeSyncAgentPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '',
      },
      'Take ownership of files or other objects' => {
        name:           'SeTakeOwnershipPrivilege',
        policy_type:    'Privilege Rights',
        policy_default: '*S-1-5-32-544',
      },
      # Security Options
      'Accounts: Administrator account status' => {
        name:           'EnableAdminAccount',
        policy_type:    'System Access',
        data_type:      :boolean,
        policy_default: 'enabled',
      },
      'Accounts: Block Microsoft accounts' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :multi_select,
        policy_options: { '0' => 'This policy is disabled',
                          '1' => 'Users can`t add Microsoft accounts',
                          '3' => 'Users can`t add or log on with Microsoft accounts' },
      },
      'Accounts: Guest account status' => {
        name:           'EnableGuestAccount',
        policy_type:    'System Access',
        data_type:      :boolean,
        policy_default: 'disabled',
      },
      'Accounts: Limit local account use of blank passwords to console logon only' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Accounts: Rename administrator account' => {
        name:           'NewAdministratorName',
        policy_type:    'System Access',
        data_type:      :string,
        policy_default: 'Administrator',
      },
      'Accounts: Rename guest account' => {
        name:           'NewGuestName',
        policy_type:    'System Access',
        data_type:      :string,
        policy_default: 'Guest',
      },
      'Audit: Audit the access of global system objects' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\AuditBaseObjects',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Audit: Audit the use of Backup and Restore privilege' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\FullPrivilegeAuditing',
        reg_type:       '3',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy',
        policy_type:    'Registry Values',
        reg_type:       '4',
        data_type:      :boolean,
      },
      'Audit: Shut down system immediately if unable to log security audits' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\CrashOnAuditFail',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'DCOM: Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax' => {
        name:           'MACHINE\Software\Policies\Microsoft\Windows NT\DCOM\MachineAccessRestriction',
        reg_type:       '1',
        policy_type:    'Registry Values',
        data_type:      :string,
      },
      'DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax' => {
        name:           'MACHINE\Software\Policies\Microsoft\Windows NT\DCOM\MachineLaunchRestriction',
        reg_type:       '1',
        policy_type:    'Registry Values',
        data_type:      :string,
      },
      'Devices: Allow undock without having to log on' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\UndockWithoutLogon',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Devices: Allowed to format and eject removable media' => {
        name:           'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD',
        reg_type:       '1',
        policy_type:    'Registry Values',
        data_type:      :multi_select,
        policy_options: { '0' => 'Administrators',
                          '1' => 'Administrators and Power Users',
                          '2' => 'Administrators and Interactive Users' },
      },
      'Devices: Prevent users from installing printer drivers' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Devices: Restrict CD-ROM access to locally logged-on user only' => {
        name:           'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateCDRoms',
        reg_type:       '1',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Devices: Restrict floppy access to locally logged-on user only' => {
        name:           'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateFloppies',
        reg_type:       '1',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Domain member: Digitally encrypt or sign secure channel data (always)' => {
        name:           'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Domain member: Digitally encrypt secure channel data (when possible)' => {
        name:           'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Domain member: Digitally sign secure channel data (when possible)' => {
        name:           'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Domain member: Disable machine account password changes' => {
        name:           'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Domain member: Maximum machine account password age' => {
        name:           'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :integer,
      },
      'Domain member: Require strong (Windows 2000 or later) session key' => {
        name:           'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Interactive logon: Display user information when the session is locked' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLockedUserId',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :multi_select,
        policy_options: { '1' => 'User display name, domain and user names',
                          '2' => 'User display name only',
                          '3' => 'Do not display user information' },
      },
      'Interactive logon: Do not display last user name' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Interactive logon: Do not require CTRL+ALT+DEL' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Interactive logon: Message title for users attempting to log on' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption',
        reg_type:       '1',
        policy_type:    'Registry Values',
        data_type:      :string,
      },
      'Interactive logon: Message text for users attempting to log on' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText',
        reg_type:       '7',
        policy_type:    'Registry Values',
        data_type:      :string,
      },
      'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' => {
        name:           'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount',
        reg_type:       '1',
        policy_type:    'Registry Values',
        data_type:      :integer,
      },
      'Interactive logon: Prompt user to change password before expiration' => {
        name:           'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :integer,
      },
      'Interactive logon: Require Domain Controller authentication to unlock workstation' => {
        name:           'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Interactive logon: Require smart card' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Interactive logon: Smart card removal behavior' => {
        name:           'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption',
        reg_type:       '1',
        policy_type:    'Registry Values',
        data_type:      :multi_select,
        policy_options: { '0' => 'No Action',
                          '1' => 'Lock Workstation',
                          '2' => 'Force Logoff',
                          '3' => 'Disconnect if a Remote Desktop Services session' },
      },
      'Interactive logon: Machine inactivity limit' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :integer,
      },
      'Interactive logon: Machine account lockout threshold' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :integer,
      },
      'Microsoft network client: Digitally sign communications (always)' => {
        name:           'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Microsoft network client: Digitally sign communications (if server agrees)' => {
        name:           'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Microsoft network client: Send unencrypted password to third-party SMB servers' => {
        name:           'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Microsoft network server: Amount of idle time required before suspending session' => {
        name:           'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :integer,
      },
      'Microsoft network server: Digitally sign communications (always)' => {
        name:           'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Microsoft network server: Digitally sign communications (if client agrees)' => {
        name:           'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Microsoft network server: Disconnect clients when logon hours expire' => {
        name:           'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableForcedLogOff',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Microsoft network server: Server SPN target name validation level' => {
        name:           'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :multi_select,
        policy_options: { '0' => 'Off',
                          '1' => 'Accept if provided by client',
                          '2' => 'Required from client' },
      },
      'Network access: Allow anonymous SID/name translation' => {
        name:           'LSAAnonymousNameLookup',
        policy_type:    'System Access',
        data_type:      :boolean,
      },
      'Network access: Do not allow anonymous enumeration of SAM accounts' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Network access: Do not allow anonymous enumeration of SAM accounts and shares' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Network access: Do not allow storage of passwords and credentials for network authentication' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Network access: Let Everyone permissions apply to anonymous users' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Network access: Named Pipes that can be accessed anonymously' => {
        name:           'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes',
        reg_type:       '7',
        policy_type:    'Registry Values',
        data_type:      :string,
      },
      'Network access: Remotely accessible registry paths' => {
        name:           'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine',
        reg_type:       '7',
        policy_type:    'Registry Values',
        data_type:      :string,
      },
      'Network access: Remotely accessible registry paths and sub-paths' => {
        name:           'MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine',
        reg_type:       '7',
        policy_type:    'Registry Values',
        data_type:      :string,
      },
      'Network access: Restrict anonymous access to Named Pipes and Shares' => {
        name:           'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RestrictNullSessAccess',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Network access: Restrict clients allowed to make remote calls to SAM' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM',
        reg_type:       '1',
        policy_type:    'Registry Values',
        data_type:      :string,
      },
      'Network access: Shares that can be accessed anonymously' => {
        name:           'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares',
        reg_type:       '7',
        policy_type:    'Registry Values',
        data_type:      :string,
      },
      'Network access: Sharing and security model for local accounts' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :multi_select,
        policy_options: { '0' => 'Classic - local users authenticate as themselves',
                          '1' => 'Guest only - local users authenticate as Guest' },
      },
      'Network security: Allow Local System to use computer identity for NTLM' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Network security: Allow LocalSystem NULL session fallback' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\allownullsessionfallback',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Network Security: Allow PKU2U authentication requests to this computer to use online identities' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Network security: Configure encryption types allowed for Kerberos' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :multi_select,
        policy_options: { '1 '         => 'DES_CBC_CRC',
                          '2 '         => 'DES_CBC_MB5',
                          '3 '         => 'DES_CBC_CRC,DES_CBC_MB5,',
                          '4 '         => 'RC4_HMAC_MD5',
                          '5 '         => 'DES_CBC_CRC,RC4_HMAC_MD5,',
                          '6 '         => 'DES_CBC_MB5,RC4_HMAC_MD5,',
                          '7 '         => 'DES_CBC_CRC,DES_CBC_MB5,RC4_HMAC_MD5,',
                          '8 '         => 'AES128_HMAC_SHA1',
                          '9 '         => 'DES_CBC_CRC,AES128_HMAC_SHA1,',
                          '10'         => 'DES_CBC_MB5,AES128_HMAC_SHA1,',
                          '11'         => 'DES_CBC_CRC,DES_CBC_MB5,AES128_HMAC_SHA1,',
                          '12'         => 'RC4_HMAC_MD5,AES128_HMAC_SHA1,',
                          '13'         => 'DES_CBC_CRC,RC4_HMAC_MD5,AES128_HMAC_SHA1,',
                          '14'         => 'DES_CBC_MB5,RC4_HMAC_MD5,AES128_HMAC_SHA1,',
                          '15'         => 'DES_CBC_CRC,DES_CBC_MB5,RC4_HMAC_MD5,AES128_HMAC_SHA1,',
                          '16'         => 'AES256_HMAC_SHA1',
                          '17'         => 'DES_CBC_CRC,AES256_HMAC_SHA1,',
                          '18'         => 'DES_CBC_MB5,AES256_HMAC_SHA1,',
                          '19'         => 'DES_CBC_CRC,DES_CBC_MB5,AES256_HMAC_SHA1,',
                          '20'         => 'RC4_HMAC_MD5,AES256_HMAC_SHA1,',
                          '21'         => 'DES_CBC_CRC,RC4_HMAC_MD5,AES256_HMAC_SHA1,',
                          '22'         => 'DES_CBC_MB5,RC4_HMAC_MD5,AES256_HMAC_SHA1,',
                          '23'         => 'DES_CBC_CRC,DES_CBC_MB5,RC4_HMAC_MD5,AES256_HMAC_SHA1,',
                          '24'         => 'AES128_HMAC_SHA1,AES256_HMAC_SHA1,',
                          '25'         => 'DES_CBC_CRC,AES128_HMAC_SHA1,AES256_HMAC_SHA1,',
                          '26'         => 'DES_CBC_MB5,AES128_HMAC_SHA1,AES256_HMAC_SHA1,',
                          '27'         => 'DES_CBC_CRC,DES_CBC_MB5,AES128_HMAC_SHA1,AES256_HMAC_SHA1,',
                          '28'         => 'RC4_HMAC_MD5,AES128_HMAC_SHA1,AES256_HMAC_SHA1,',
                          '29'         => 'DES_CBC_CRC,RC4_HMAC_MD5,AES128_HMAC_SHA1,AES256_HMAC_SHA1,',
                          '30'         => 'DES_CBC_MB5,RC4_HMAC_MD5,AES128_HMAC_SHA1,AES256_HMAC_SHA1,',
                          '31'         => 'DES_CBC_CRC,DES_CBC_MB5,RC4_HMAC_MD5,AES128_HMAC_SHA1,AES256_HMAC_SHA1,',
                          '2147483616' => 'Future encryption types',
                          '2147483617' => 'DES_CBC_CRC,Future encryption types',
                          '2147483618' => 'DES_CBC_MB5,Future encryption types',
                          '2147483619' => 'DES_CBC_CRC,DES_CBC_MB5,Future encryption types',
                          '2147483620' => 'RC4_HMAC_MD5,Future encryption types',
                          '2147483621' => 'DES_CBC_CRC,RC4_HMAC_MD5,Future encryption types',
                          '2147483622' => 'DES_CBC_MB5,RC4_HMAC_MD5,Future encryption types',
                          '2147483623' => 'DES_CBC_CRC,DES_CBC_MB5,RC4_HMAC_MD5,Future encryption types',
                          '2147483624' => 'AES128_HMAC_SHA1,Future encryption types',
                          '2147483625' => 'DES_CBC_CRC,AES128_HMAC_SHA1,Future encryption types',
                          '2147483626' => 'DES_CBC_MB5,AES128_HMAC_SHA1,Future encryption types',
                          '2147483627' => 'DES_CBC_CRC,DES_CBC_MB5,AES128_HMAC_SHA1,Future encryption types',
                          '2147483628' => 'RC4_HMAC_MD5,AES128_HMAC_SHA1,Future encryption types',
                          '2147483629' => 'DES_CBC_CRC,RC4_HMAC_MD5,AES128_HMAC_SHA1,Future encryption types',
                          '2147483630' => 'DES_CBC_MB5,RC4_HMAC_MD5,AES128_HMAC_SHA1,Future encryption types',
                          '2147483631' => 'DES_CBC_CRC,DES_CBC_MB5,RC4_HMAC_MD5,AES128_HMAC_SHA1,Future encryption types',
                          '2147483632' => 'AES256_HMAC_SHA1,Future encryption types',
                          '2147483633' => 'DES_CBC_CRC,AES256_HMAC_SHA1,Future encryption types',
                          '2147483634' => 'DES_CBC_MB5,AES256_HMAC_SHA1,Future encryption types',
                          '2147483635' => 'DES_CBC_CRC,DES_CBC_MB5,AES256_HMAC_SHA1,Future encryption types',
                          '2147483636' => 'RC4_HMAC_MD5,AES256_HMAC_SHA1,Future encryption types',
                          '2147483637' => 'DES_CBC_CRC,RC4_HMAC_MD5,AES256_HMAC_SHA1,Future encryption types',
                          '2147483638' => 'DES_CBC_MB5,RC4_HMAC_MD5,AES256_HMAC_SHA1,Future encryption types',
                          '2147483639' => 'DES_CBC_CRC,DES_CBC_MB5,RC4_HMAC_MD5,AES256_HMAC_SHA1,Future encryption types',
                          '2147483640' => 'AES128_HMAC_SHA1,AES256_HMAC_SHA1,Future encryption types',
                          '2147483641' => 'DES_CBC_CRC,AES128_HMAC_SHA1,AES256_HMAC_SHA1,Future encryption types',
                          '2147483642' => 'DES_CBC_MB5,AES128_HMAC_SHA1,AES256_HMAC_SHA1,Future encryption types',
                          '2147483643' => 'DES_CBC_CRC,DES_CBC_MB5,AES128_HMAC_SHA1,AES256_HMAC_SHA1,Future encryption types',
                          '2147483644' => 'RC4_HMAC_MD5,AES128_HMAC_SHA1,AES256_HMAC_SHA1,Future encryption types',
                          '2147483645' => 'DES_CBC_CRC,RC4_HMAC_MD5,AES128_HMAC_SHA1,AES256_HMAC_SHA1,Future encryption types',
                          '2147483646' => 'DES_CBC_MB5,RC4_HMAC_MD5,AES128_HMAC_SHA1,AES256_HMAC_SHA1,Future encryption types',
                          '2147483647' => 'DES_CBC_CRC,DES_CBC_MB5,RC4_HMAC_MD5,AES128_HMAC_SHA1,AES256_HMAC_SHA1,Future encryption types' },
      },
      'Network security: Do not store LAN Manager hash value on next password change' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Network security: Force logoff when logon hours expire' => {
        name:           'ForceLogoffWhenHourExpire',
        policy_type:    'System Access',
        data_type:      :boolean,
        policy_default: 'disabled',
      },
      'Network security: LAN Manager authentication level' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :multi_select,
        policy_options: { '0' => 'Send LM & NTLM responses',
                          '1' => 'Send LM & NTLM - use NTLMv2 session security if negotiated',
                          '2' => 'Send NTLM response only',
                          '3' => 'Send NTLMv2 response only',
                          '4' => 'Send NTLMv2 response only. Refuse LM',
                          '5' => 'Send NTLMv2 response only. Refuse LM & NTLM' },
      },
      'Network security: LDAP client signing requirements' => {
        name:           'MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity',
        policy_type:    'Registry Values',
        reg_type:       '4',
        data_type:      :multi_select,
        policy_options: { '0' => 'None',
                          '1' => 'Negotiate signing',
                          '2' => 'Require signing' },
      },
      'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :multi_select,
        policy_options: { '524288'    => 'Require NTLMv2 session security',
                          '536870912' => 'Require 128-bit encryption',
                          '537395200' => 'Require NTLMv2 session security,Require 128-bit encryption' },
      },
      'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec',
        policy_type:    'Registry Values',
        reg_type:       '4',
        data_type:      :multi_select,
        policy_options: { '524288'    => 'Require NTLMv2 session security',
                          '536870912' => 'Require 128-bit encryption',
                          '537395200' => 'Require NTLMv2 session security,Require 128-bit encryption' },
      },
      'Recovery console: Allow automatic administrative logon' => {
        name:           'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Recovery console: Allow floppy copy and access to all drives and all folders' => {
        name:           'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SetCommand',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Shutdown: Allow system to be shut down without having to log on' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'Shutdown: Clear virtual memory pagefile' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown',
        policy_type:    'Registry Values',
        reg_type:       '4',
        data_type:      :boolean,
      },
      'System cryptography: Force strong key protection for user keys stored on the computer' => {
        name:           'MACHINE\Software\Policies\Microsoft\Cryptography\ForceKeyProtection',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :multi_select,
        policy_options: { '0' => 'User input is not required when new keys are stored and used',
                          '1' => 'User is prompted when the key is first used',
                          '2' => 'User must enter a password each time they use a key' },
      },
      'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'System objects: Require case insensitivity for non-Windows subsystems' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive',
        policy_type:    'Registry Values',
        reg_type:       '4',
        data_type:      :boolean,
        policy_default: 'enabled',
      },
      'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Session Manager\ProtectionMode',
        policy_type:    'Registry Values',
        reg_type:       '4',
        data_type:      :boolean,
      },
      'System settings: Optional subsystems' => {
        name:           'MACHINE\System\CurrentControlSet\Control\Session Manager\SubSystems\optional',
        policy_type:    'Registry Values',
        reg_type:       '7',
        data_type:      :string,
      },
      'System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies' => {
        name:           'MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\AuthenticodeEnabled',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'User Account Control: Admin Approval Mode for the Built-in Administrator account' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :multi_select,
        policy_options: { '0' => 'Elevate without prompting',
                          '1' => 'Prompt for credentials on the secure desktop',
                          '2' => 'Prompt for consent on the secure desktop',
                          '3' => 'Prompt for credentials',
                          '4' => 'Prompt for consent',
                          '5' => 'Prompt for consent for non-Windows binaries' },
      },
      'User Account Control: Behavior of the elevation prompt for standard users' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :multi_select,
        policy_options: { '0' => 'Automatically deny elevation requests',
                          '1' => 'Prompt for credentials on the secure desktop',
                          '3' => 'Prompt for credentials' },
      },
      'User Account Control: Detect application installations and prompt for elevation' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'User Account Control: Only elevate executable files that are signed and validated' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'User Account Control: Only elevate UIAccess applications that are installed in secure locations' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'User Account Control: Run all administrators in Admin Approval Mode' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'User Account Control: Switch to the secure desktop when prompting for elevation' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      'User Account Control: Virtualize file and registry write failures to per-user locations' => {
        name:           'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization',
        reg_type:       '4',
        policy_type:    'Registry Values',
        data_type:      :boolean,
      },
      # Setting is ignored: https://msdn.microsoft.com/en-us/library/cc232772.aspx
      'Accounts: Require Login to Change Password' => {
        name:           'RequireLogonToChangePassword',
        policy_type:    'System Access',
        data_type:      :boolean,
        policy_default: 'disabled',
      },
    }
  end
end
