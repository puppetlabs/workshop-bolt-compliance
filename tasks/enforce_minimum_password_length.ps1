Import-Module SecurityPolicyDSC -Force
$commonParams = @{
  Name = 'AccountPolicy'
  Property = @{ 
    Name ='Minimum_Password_Length'
    Minimum_Password_Length = 14
  }
  ModuleName = 'SecurityPolicyDSC'
  Verbose = $false
}

$state = Invoke-DscResource @commonParams -Method Get

if (-not $state.InDesiredState) {
  Invoke-DscResource @commonParams -Method Set
}

return Invoke-DscResource @commonParams -Method Get


