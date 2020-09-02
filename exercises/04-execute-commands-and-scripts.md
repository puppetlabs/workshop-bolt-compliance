# Exercise #4 - Execute Commands and Scripts

## Steps

- Open a shell and change to the boltshop directory.

- From your shell, run  `bolt command run 'write-output "hello world!"' --targets windows`

- From your shell, run `bolt script run examples/helloworld.ps1 --targets windows`

Sample Output:

```
PS C:\code\boltshop> bolt script run .\examples\helloworld.ps1 
Started on boltshop99.classroom.puppet.com...
Finished on boltshop99.classroom.puppet.com:
  STDOUT:
    Hello World!
Successful on 1 target: boltshop99.classroom.puppet.com
Ran on 1 target in 19.15 sec
```
