Import-Module SecurityPolicyDSC -Force
$commonParams = @{
  Name = 'AccountPolicy'
  Property = @{ 
    Name ='Password_must_meet_complexity_requirements'
    Password_must_meet_complexity_requirements = 'Enabled'
  }
  ModuleName = 'SecurityPolicyDSC'
  Verbose = $false
}

$state = Invoke-DscResource @commonParams -Method Get

if (-not $state.InDesiredState) {
  Invoke-DscResource @commonParams -Method Set
}

return Invoke-DscResource @commonParams -Method Get


