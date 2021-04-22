# Exercise #4 - Use Bolt to check for current state

## Steps

- Open a shell and change to the boltshop directory.

- Run the following commands:

To check the minimum password age is at least 7:

`bolt command run "grep PASS_MIN_DAYS /etc/login.defs" -t nix`

To check whether the root login is disabled:

`bolt command run "grep PermitRootLogin /etc/ssh/sshd_config" -t nix`

To check whether the FTP server package is not installed:

`bolt task run package name=vsftpd action=status -t nix`


# Exercise #4 - Continued

- Run the following commands:

To check the file permissions of the bootloader configuration are 0600:

`bolt command run "ls -l /boot/grub2/grub.cfg" -t nix`

To check whether the umask is at least 027 (in multiple locations):

`bolt script run scripts/umask_check.sh -t nix`


# Exercise #4 - Continued - Windows

- Run the following commands:

To execute a pre-requisite for Windows systems:

`bolt plan run compliance::prep_windows targets=win` 

To check for numerous Windows password policies:

`bolt task run compliance::check_password_policies -t win`
