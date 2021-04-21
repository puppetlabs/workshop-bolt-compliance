# Exercise #6 - Use Puppet code with Bolt to remediate CIS settings


 - Run the following command:


`bolt plan run secure_linux_cis time_servers='["0.us.pool.ntp.org","1.us.pool.ntp.org"]'  profile_type=workstation nodes=nix`

*if running bolt from Windows Powershell use this command:
'Invoke-BoltPlan -Name secure_linux_cis -Params '@params.json' -Targets nix'

- To verify some results, run:

`bolt command run "grep PermitRootLogin /etc/ssh/sshd_config" -t nix`

`bolt script run scripts/umask_check.sh -t nix`


# Exercise #6 - Continued - Windows

 - Run the following command:
 
 `bolt apply code/acct_lockout_settings.pp -t win`
 
 
- To verify some results, run:

`bolt task run compliance::check_password_policies -t win`
