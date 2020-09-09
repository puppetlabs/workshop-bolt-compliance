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
compliance::helloworld       Say Hello World!
compliance::windowsfeature   Installs a Windows Feature
facts                      Gather system facts
package                    Manage and inspect the state of packages
pkcs7::secret_createkeys   Create a key pair
pkcs7::secret_decrypt      Encrypt sensitive data with pkcs7
pkcs7::secret_encrypt      Encrypt sensitive data with pkcs7
puppet_agent::install      Install the Puppet agent package
puppet_agent::version      Get the version of the Puppet agent package installed. Returns nothing if none present.
puppet_conf                Inspect puppet agent configuration settings
reboot                     Reboots a machine
reboot::last_boot_time     Gets the last boot time of a Linux or Windows system
service                    Manage and inspect the state of services
terraform::apply           Apply an HCL manifest
terraform::destroy         Destroy resources managed with Terraform
terraform::initialize      Initialize a Terraform project directory
terraform::output          JSON representation of Terraform outputs

MODULEPATH:
C:/code/boltshop/modules
```
