Fortinet Config Parse Tool v0.1.1

This tool is used to parse a Fortinet Fortigate configuration file into a human readable TSV format.

Currently, three types of objects are parsed:
-Addresses
-Groups
-Policies (Rules)
Planned types:
-Vips
-Routes
-Users

In the near future I hope to have this reading only a single configuration file. 

For each type, the tool looks for an appropriate input file (eg: policy.txt to process policies). 
These input files should contain only the objects, and not the 'config firewall xxxxxx' / 'end' statements.
Example (While this example is a policy, the same structure should be used for the address and group files)
----------------
edit 1
   set srcintf "port1"
   set dstintf "port2"
   ....
   ....
next
edit 2
   ....
----------------

After running the program, I personally recommend compiling them all into one excel spreadsheet. 
I've included an example. Note that for readability, the groups tab has had it's rows and columns transposed,
making the column an entire group. I find this much easier to read.