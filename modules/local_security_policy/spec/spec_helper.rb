# frozen_string_literal: true

require 'puppetlabs_spec_helper/module_spec_helper'

def fixtures_path
  proj_root = File.expand_path(File.join(File.dirname(__FILE__), '..'))
  fixtures_path = File.join(proj_root, 'spec', 'fixtures')
  fixtures_path
end

RSpec.configure do |c|
  c.formatter = 'documentation'
  c.mock_with :rspec
  c.fail_fast = true
end

at_exit { RSpec::Puppet::Coverage.report! }
