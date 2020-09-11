[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
If (!(Get-PackageProvider Nuget)) { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force }
If (!(Get-PSRepository PSGallery)) { Register-PSRepository -Default -Force }
IF (!(Get-Module SecurityPolicyDSC)) { Install-Module -Name SecurityPolicyDSC -Force }
