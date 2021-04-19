# Exercise #2: Downloading the Bolt Project

This project: [download link](https://github.com/puppetlabs/workshop-bolt-compliance)

## Steps

- Clone or download zip from the above link.

- Place into a ‘boltshop’ directory where you like or extract where you like and rename directory to 'boltshop'.

- Open a shell and change to that directory.

Run `bolt task show` to verify you have tasks that start with `compliance::`.

*Note: If you are using PowerShell, make sure your boltshop path is respecting case sensitivity.*


Sample Output:

```
PS C:\code\boltshop> bolt task show
Tasks
  compliance::check_password_policies
  compliance::enforce_minimum_password_length
  compliance::enforce_password_complexity
  compliance::helloworld                          Say Hello World!
  compliance::windows_prep
  facts                                           Gather system facts
  http_request                                    Make a HTTP or HTTPS request.
  package                                         Manage and inspect the state of packages
  pkcs7::secret_createkeys                        Create a key pair
  ...
```
