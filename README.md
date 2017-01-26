##Omnislash

Omnislash is a python3 script designed to take the output from masscan (https://github.com/robertdavidgraham/masscan) and clean it up for automated use by other tools. In its current form, it will take the scan results and output each port to its own list of IPs with the time, range and port number appended to the name of the file. 

The ultimate goal of this tool is to build in support for many other tools so that they can all be kicked off from a single command.

###Usage

Run from the command line using the following syntax:

python3 omnislash.py -t 192.168.1.0/24 -p 21,22,137 -o output -a

Full details for options can be found within the script


###Supported tools

The tools currently supported for automation by Omnislash are as follows:

-nikto (https://github.com/sullo/nikto)

-enum4linux (https://github.com/portcullislabs/enum4linux)

-showmount (http://packages.ubuntu.com/precise/net/nfs-common)

-ftp-anon.nse (https://svn.nmap.org/nmap/scripts/ftp-anon.nse)

###To do

-Continue adding support for more tools/ports

-Configure plugins to take arguments for port results to scan against (allow for more useability- will require replacing getopt)

-Clean up output so there aren't as many files created (compile results into one report, put raw results in a folder?)

-Implement threading to run all tool plugins simultaneously for faster results (as an option as this would be extremely noisy)

-Work on a timeout/faster processing for HTTPS ports in Nikto

-Combine all ports when running enum4linux and only run against 1 set of IPs (reduces duplicate results)

###Known Issues

-Nikto can hang while scanning HTTPS (30 minutes+ for each IP)

###Disclaimer

I did not write any of the tools used by Omnislash and do not take credit for doing so. Omnislash is just meant to make using these tools easier with a single kick-off point for automation.

It has been provided for testing and academic purposes only. Do not use this tool against networks that you do not own or have express/strict written consent to test against. Do not use for illegal purposes.
