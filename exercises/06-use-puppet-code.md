# Exercise #6 - Use Puppet code with Bolt to remediate CIS settings


 - Run the following command (please ensure that you change the node name to your assigned number):


`bolt plan run secure_linux_cis time_servers='["0.us.pool.ntp.org","1.us.pool.ntp.org"]'  profile_type=workstation nodes=bolt91620nix000.classroom.puppet.com`


- To verify some results, run:

`bolt command run "cat /etc/ssh/sshd_config | grep PermitRootLogin" -t nix`

`bolt script run scripts/umask_check.sh -t nix`


# Exercise #6 - Continued - Windows

 - Run the following command:
 
 `bolt apply code/acct_lockout_settings.pp -t win`
 
 
- To verify some results, run:

`bolt task run compliance::check_password_policies -t win`
