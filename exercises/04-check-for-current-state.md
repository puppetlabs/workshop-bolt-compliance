# Exercise #4 - Use Bolt to check for current state

## Steps

- Open a shell and change to the boltshop directory.

- Run the following commands:


`bolt command run "grep PASS_MIN_DAYS /etc/login.defs" -t nix`


`bolt command run "grep PermitRootLogin /etc/ssh/sshd_config" -t nix`


`bolt task run package name=vsftpd action=status -t nix`


# Exercise #4 - Continued

- Run the following commands:

`bolt command run "ls -l /boot/grub2/grub.cfg" -t nix`


`bolt script run scripts/umask_check.sh -t nix`


# Exercise #4 - Continued - Windows

- Run the following commands:

`bolt plan run compliance::prep_windows targets=nix`   to set some Windows prereqs 

`bolt task run compliance::check_password_policies -t win`
