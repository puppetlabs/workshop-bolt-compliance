# frozen_string_literal: false

require 'spec_helper'
provider_class = Puppet::Type.type(:local_security_policy).provider(:policy)

describe provider_class do
  subject { provider_class }

  before :each do
    Puppet::Util.stubs(:which).with('secedit').returns('c:\\tools\\secedit')
    infout = StringIO.new
    sdbout = StringIO.new
    allow(SecurityPolicy).to receive(:read_policy_settings).and_return(inf_data)
    allow(Tempfile).to receive(:new).with('infimport').and_return(infout)
    allow(Tempfile).to receive(:new).with('sdbimport').and_return(sdbout)
    allow(File).to receive(:file?).and_return(true)
    # the below mock seems to be required or rspec complains
    allow(File).to receive(:file?).with(%r{facter}).and_return(true)
    allow(SecurityPolicy).to receive(:temp_file).and_return(secdata)
    provider_class.stubs(:secedit).with(['/configure', '/db', 'sdbout', '/cfg', 'infout', '/quiet'])
    provider_class.stubs(:secedit).with(['/export', '/cfg', secdata, '/quiet'])
  end

  let(:security_policy) do
    SecurityPolicy.new
  end

  let(:inf_data) do
    regexp = '\xEF\xBB\xBF'
    regexp.force_encoding 'utf-8'
    inffile_content = File.read(secdata).encode('utf-8', universal_newline: true).gsub(regexp, '')
    PuppetX::IniFile.new(content: inffile_content)
  end
  # mock up the data which was gathered on a real windows system
  let(:secdata) do
    File.join(fixtures_path, 'unit', 'secedit.inf')
  end

  let(:groupdata) do
    file = File.join(fixtures_path, 'unit', 'group.txt')
    regexp = '\xEF\xBB\xBF'
    regexp.force_encoding 'utf-8'
    File.open(file, 'r') { |f| f.read.encode('utf-8', universal_newline: true).gsub(regexp, '') }
  end

  let(:userdata) do
    file = File.join(fixtures_path, 'unit', 'useraccount.txt')
    regexp = '\xEF\xBB\xBF'
    regexp.force_encoding 'utf-8'
    File.open(file, 'r') { |f| f.read.encode('utf-8', universal_newline: true).gsub(regexp, '') }
  end

  let(:facts) do
    { is_virtual: 'false', operatingsystem: 'windows' }
  end

  let(:resource) do
    Puppet::Type.type(:local_security_policy).new(
      name: 'Network access: Let Everyone permissions apply to anonymous users',
      ensure: 'present',
      policy_setting: 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
      policy_type: 'Registry Values',
      policy_value: 'disabled',
    )
  end

  let(:provider) do
    provider_class.new(resource)
  end

  it 'creates instances without error' do
    instances = provider_class.instances
    expect(instances.class).to eq(Array)
    expect(instances.count).to be >= 114
  end

  # if you get this error, your are missing a entry in the lsp_mapping under puppet_x/security_policy
  # either its a type, case, or missing entry
  it 'lsp_mapping should contain all the entries in secdata file' do
    inffile = SecurityPolicy.read_policy_settings
    missing_policies = {}
    # message = lambda { |pol| 'Missing policy, check the lsp mapping for something like: #{pol}\n' }

    inffile.sections.each do |section|
      next if section == 'Unicode'
      next if section == 'Version'
      inffile[section].each do |name, value|
        begin
          SecurityPolicy.find_mapping_from_policy_name(name)
        rescue KeyError => e
          puts e.message
          if value && section == 'Registry Values'
            reg_type = value.split(',').first
            missing_policies[name] = { name: name, policy_type: section, reg_type: reg_type }
          else
            missing_policies[name] = { name: name, policy_type: section }
          end
        end
      end
    end
    expect(missing_policies.count).to eq(0), 'Missing policy, check the lsp mapping'
  end

  xit 'ensure instances works' do
    instances = Puppet::Type.type(:local_security_policy).instances
    expect(instances.count).to be > 1
  end

  describe 'write output' do
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Recovery console: Allow automatic administrative logon',
        ensure: 'present',
        policy_setting: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
        policy_type: 'Registry Values',
        policy_value: 'disabled',
      )
    end

    xit 'writes out the file correctly' do
      provider.create
    end
  end

  describe 'resource is removed' do
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Network access: Let Everyone permissions apply to anonymous users',
        ensure: 'absent',
        policy_setting: 'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous',
        policy_type: 'Registry Values',
        policy_value: 'disabled',
      )
    end

    it 'exists? should be false' do
      expect(provider.exists?).to eq(false)
    end
  end

  describe 'resource is present' do
    let(:secdata) do
      File.join(fixtures_path, 'unit', 'short_secedit.inf')
    end

    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Recovery console: Allow automatic administrative logon',
        ensure: 'present',
        policy_setting: 'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
        policy_type: 'Registry Values',
        policy_value: 'disabled',
      )
    end

    it 'exists? should be true' do
      expect(provider).to receive(:create).exactly(0).times
    end
  end

  describe 'resource is absent' do
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Recovery console: Allow automatic administrative logon',
        ensure: 'present',
        policy_setting: '1MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
        policy_type: 'Registry Values',
        policy_value: 'enabled',
      )
    end

    it 'exists? should be false' do
      expect(provider.exists?).to eq(false)
      allow(provider).to receive(:create).exactly(1).times
    end
  end

  describe 'resource is changed' do
    let(:secdata) do
      File.join(fixtures_path, 'unit', 'short_secedit.inf')
    end

    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Accounts: Administrator account status',
        ensure: 'present',
        policy_setting: 'EnableAdminAccount',
        policy_type: 'System Access',
        policy_value: 'disabled',
      )
    end

    it 'exists? should be true' do
      expect(provider).to receive(:create).exactly(0).times
    end
  end

  describe 'resource is created' do
    let(:resource) do
      Puppet::Type.type(:local_security_policy).new(
        name: 'Accounts: Block Microsoft accounts',
        ensure: 'present',
        policy_setting: 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser',
        policy_type: 'Registry Values',
        policy_value: 'Users can`t add Microsoft accounts',
      )
    end

    it 'exists? should be false' do
      expect(provider.exists?).to eq(false)
      allow(provider).to receive(:create).exactly(1).times
    end
  end

  it 'is an instance of Puppet::Type::Local_security_policy::ProviderPolicy' do
    expect(provider).to be_an_instance_of Puppet::Type::Local_security_policy::ProviderPolicy
  end
end
