require 'puppetlabs_spec_helper/rake_tasks'

# Must clear as it will not override the existing puppet-lint rake task since we require to import for
# the PuppetLint::RakeTask
Rake::Task[:lint].clear
# Relative is not able to be set within the context of PuppetLint::RakeTask
PuppetLint.configuration.relative = true
PuppetLint::RakeTask.new(:lint) do |config|
  config.fail_on_warnings = true
  config.disable_checks = [
      '80chars',
      'class_inherits_from_params_class',
      'class_parameter_defaults',
      'documentation']
  config.ignore_paths = ["vendor/**/*.pp","spec/**/*.pp", "pkg/**/*.pp"]
end

desc "Run syntax, lint, and spec tests."
task :test => [
  :syntax,
  :lint,
  :spec,
]
