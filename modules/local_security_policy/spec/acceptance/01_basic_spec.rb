# frozen_string_literal: false

require 'spec_helper_acceptance'

describe 'local_security_policy', unless: UNSUPPORTED_PLATFORMS.include?(fact('os.family')) do
  ENV['no_proxy'] = default
  context 'with local windows security settings ' do
    pp = <<-LSP

      # Computer Configuration of local security policies
      $local_security_policy_settings = lookup(
        'local_security_policy::settings',
        # Data structure
        Hash[String, Struct[{
          ensure         => Optional[Enum['present', 'absent']],
          policy_value   => Optional[String],
          domain_managed => Optional[Boolean],
        }]],
        # Merge behaviour
        { 'strategy'        => 'deep',
          'knockout_prefix' => '--',
        },
      )
      if $local_security_policy_settings {
        $local_security_policy_settings.each |$key, $value| {
          if $value[domain_managed] != true {
            local_security_policy { $key:
              ensure       => $value[ensure],
              policy_value => $value[policy_value],
            }
          }
        }
      }
    LSP

    it ' works idempotently with no errors' do
      # Run it twice and test for idempotency
      default.logger.notify 'This can take a while, so grab a coffee'
      apply_manifest(pp, catch_failures: true)
      apply_manifest(pp, catch_changes:  true)
    end
  end
end
