# Exercise #3 - Managing your inventory.yaml file

## Steps

- Edit inventory.yaml

- Replace the 00 in the `uri` field with your assigned VM number for BOTH the Windows and Linux targets.

```
groups:
  - name: windows
    targets:
      - uri: bolt0422win00.classroom.puppet.com
        alias: win
    config:
      transport: winrm
      winrm:
        user: Administrator
        password: Puppetlabs!
        ssl: false
  - name: linux
    targets:
      - uri: bolt0422nix00.classroom.puppet.com
        alias: nix
...
```

- Save inventory.yaml

- OPEN this link for your SSH key: https://bit.ly/BoltHostKey
- CREATE a file in your bolt project directory named student.pem and copy the SSH key into this file, save.

- From your command shell (ensure you are in the boltshop directory), run `bolt inventory show --targets all`

Sample Output:

```
PS C:\code\boltshop> bolt inventory show -t all
bolt0422win0.classroom.puppet.com
bolt0422nix0.classroom.puppet.com
2 targets
```

- To test connectivity to your nodes, run `bolt command run hostname --targets all`

- Verify you get a response from each target (1 Windows and 1 Linux) and there are no errors
