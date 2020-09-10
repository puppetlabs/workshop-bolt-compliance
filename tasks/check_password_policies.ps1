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

return $state