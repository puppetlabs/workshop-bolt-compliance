# Exercise #1: Installing Bolt

## Steps

1. Go to [the Bolt installation documentation](https://puppet.com/docs/bolt/latest/bolt_installing.html)

- Follow the instructions to install Bolt for your OS platform.
 For example, if running Windows follow the instructions for installing Bolt with MSI.
 
 If running Windows and you have a command shell open when you install Bolt, ensure you close and reopen the command shell so that the environmental variables are    picked up



2. Open a command shell and run `bolt --version`

Sample output:

```
PS C:\code\boltshop> bolt --version
3.7.0
```

You need **at least** version 2.24.0 installed. If you on an earlier release, visit [the Bolt documentation](https://puppet.com/docs/bolt/latest/bolt_installing.html).

- If you get an error running Bolt on Windows, it may be due to a security restriction on some Windows systems. Follow the 'Change execution policy restrictions' section in the installing Bolt documentation.
It has you run Powershell as an administrator and then has you run the following command `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned`
