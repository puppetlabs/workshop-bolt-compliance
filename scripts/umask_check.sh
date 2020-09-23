#!/bin/bash
#Look for umask settings in list of files

#Specify array of file names
files=( "/etc/bashrc" "/etc/login.defs" "/etc/profile" "/etc/csh.cshrc")

#Iterate over array to search for umask and output filename and results
for i in "${files[@]}"
do
    echo $i
    echo -----
    grep umask $i
    echo -----
done