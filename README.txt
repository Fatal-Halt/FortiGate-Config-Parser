Fortinet Config Parse Tool v0.3
Python 3.4

*This project is in serious need of a re-write. I'm mostly just using it when I need, so it gets little attention, hopefully someday I can give it the tune up it needs*

This tool is used to parse a Fortinet Fortigate configuration file into a human readable TSV format.

The file expects to find a configuration file named 'config.conf' in the same directory as itself. 

After running the program, I personally recommend compiling the different .tsv files into one excel spreadsheet. 
I've included an example. Note that for readability, the groups tab has had it's rows and columns transposed,
making the column an entire group. I find this much easier to read.

Planned future changes: 
-Executable
-Support for additional pieces of data:
==Interfaces and Static Routes
==Virtual IPs and IP Pools
==Non-standard services
==Users, user groups
==Administrators, Administrator Profiles
