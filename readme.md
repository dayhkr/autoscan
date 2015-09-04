#Yara Autoscan

####AutoScan is used to watch the Carbon Black server's Modules directory for new Binaries that are uploaded from the clients.  
####It will automatically unzip the files and scan them with your Yara rules.  
####If there is a hit on your rules it will query the Carbon Black server to find out where the binary has been seen and will syslog out an alert.


- autoscan.py - Main Program that uses Inotify to watch for new incoming binaries.
- gitwatch.py - Python library to watch a defined Git hub repo for new yara rules being published and automatically download those signatures.



####ToDo:  Still need to change a lot of the arguments into variables that are defined in a config file.
