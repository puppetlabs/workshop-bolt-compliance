# frozen_string_literal: true

require 'beaker-rspec/spec_helper'
require 'beaker-rspec/helpers/serverspec'
require 'beaker/puppet_install_helper'

UNSUPPORTED_PLATFORMS = ['RedHat'].freeze

unless ENV['RS_PROVISION'] == 'no' || ENV['BEAKER_provision'] == 'no'
  # Install Puppet Enterprise Agent
  run_puppet_install_helper
end

RSpec.configure do |c|
  # Project root
  proj_root = File.expand_path(File.join(File.dirname(__FILE__), '..'))

  # Readable test descriptions
  c.formatter = :documentation

  # Configure all nodes in nodeset
  c.before :suite do
    # copy hiera
    hierarchy = [
      '%{::os.release.major}',
      'common',
    ]
    write_hiera_config(hierarchy)
    copy_hiera_data('./spec/hieradata/beaker/common.yaml')
    copy_hiera_data('./spec/hieradata/beaker/2008 R2.yaml')
    copy_hiera_data('./spec/hieradata/beaker/2012 R2.yaml')
    copy_hiera_data('./spec/hieradata/beaker/2016.yaml')

    puppet_module_install(source: proj_root, module_name: 'local_security_policy')
  end
end
