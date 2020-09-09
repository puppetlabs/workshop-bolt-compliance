# Exercise #5: Use Bolt to remediate CIS settings

 - Run the following commands to remediate CIS settings:


`bolt command run "chmod 0600 /boot/grub2/grub.cfg" -t nix`


`bolt script run scripts/set_min_pass.sh -t nix`

 
 - Check that settings were properly configured:
 
 `bolt command run "ls -l /boot/grub2/grub.cfg" -t nix`
 
 `bolt command run "cat /etc/login.defs | grep PASS_MIN_DAYS" -t nix`


# Exercise #5: Continued - Windows

 - Run the following commands:
 
 tbd
 
 tbd
