# Exercise #3 - Managing a Static Inventory File

## Steps

- Edit inventory.yaml

- Replace the `uri` and `alias` fields your assigned server’s FQDN and "www", respectively.

```
groups:
  - name: windows
    targets:
      - uri: boltshop99.classroom.puppet.com
        alias: www
    config:
      transport: winrm
      winrm:
        user: Administrator
        password: Puppetlabs!
        ssl: false
```

- Open a shell and change to the boltshop directory.

- From your shell, run `bolt inventory show --targets windows`



Sample Output:

```
PS C:\code\boltshop> bolt inventory show 
boltshop99.classroom.puppet.com
1 target
```