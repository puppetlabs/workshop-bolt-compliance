# frozen_string_literal: true

require 'spec_helper'
require 'puppet_x/lsp/security_policy'

describe 'SecurityPolicy' do
  subject { SecurityPolicy }

  before :each do
    Puppet::Util.stubs(:which).with('secedit').returns('c:\\tools\\secedit')
    # Set windir environment variable
    ENV['windir'] = 'C:\Windows'
    infout = StringIO.new
    sdbout = StringIO.new
    allow(SecurityPolicy).to receive(:read_policy_settings).and_return(inf_data)
    allow(Tempfile).to receive(:new).with('infimport').and_return(infout)
    allow(Tempfile).to receive(:new).with('sdbimport').and_return(sdbout)
    allow(File).to receive(:file?).with(secdata).and_return(true)
    # the below mock seems to be required or rspec complains
    allow(File).to receive(:file?).with(%r{facter}).and_return(true)
    allow(SecurityPolicy).to receive(:temp_file).and_return(secdata)
    SecurityPolicy.stubs(:secedit).with(['/configure', '/db', 'sdbout', '/cfg', 'infout', '/quiet'])
    SecurityPolicy.stubs(:secedit).with(['/export', '/cfg', secdata, '/quiet'])
    security_policy.stubs('user_to_sid').with('*S-11-5-80-0').returns('*S-11-5-80-0')
    security_policy.stubs('sid_to_user').with('S-1-5-32-556').returns('Network Configuration Operators')
    security_policy.stubs('sid_to_user').with('*S-1-5-80-0').returns('NT_SERVICE\\ALL_SERVICES')
    security_policy.stubs('user_to_sid').with('Network Configuration Operators').returns('*S-1-5-32-556')
    security_policy.stubs('user_to_sid').with('NT_SERVICE\\ALL_SERVICES').returns('*S-1-5-80-0')
    security_policy.stubs('user_to_sid').with('N_SERVICE\\ALL_SERVICES').returns('N_SERVICE\\ALL_SERVICES')
  end

  let(:inf_data) do
    regexp = '\xEF\xBB\xBF'
    inffile_content = File.read(secdata).encode('utf-8', universal_newline: true).gsub(regexp, '')
    PuppetX::IniFile.new(content: inffile_content)
  end

  let(:secdata) do
    File.join(fixtures_path, 'unit', 'secedit.inf')
  end

  let(:security_policy) do
    SecurityPolicy.new
  end

  it 'returns user' do
    expect(security_policy.sid_to_user('S-1-5-32-556')).to eq('Network Configuration Operators')
    expect(security_policy.sid_to_user('*S-1-5-80-0')).to eq('NT_SERVICE\\ALL_SERVICES')
  end

  it 'returns sid when user is not found' do
    expect(security_policy.user_to_sid('*S-11-5-80-0')).to eq('*S-11-5-80-0')
  end

  it 'returns sid' do
    expect(security_policy.user_to_sid('Network Configuration Operators')).to eq('*S-1-5-32-556')
    expect(security_policy.user_to_sid('NT_SERVICE\\ALL_SERVICES')).to eq('*S-1-5-80-0')
  end

  it 'returns user when sid is not found' do
    expect(security_policy.user_to_sid('N_SERVICE\\ALL_SERVICES')).to eq('N_SERVICE\\ALL_SERVICES')
  end
end
