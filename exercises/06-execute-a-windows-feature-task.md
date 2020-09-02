# Exercise #6 - Execite a Windows Feature Task

## Steps

  - Open a shell and change to your boltshop directory

  - Run bolt task show boltshop::windowsfeature

  - Run the following: `bolt task run boltshop::windowsfeature --targets www action=install feature=web-webserver`

  - When completed, visit `http://<your_webserver>`
