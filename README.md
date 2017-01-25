##Omnislash

Omnislash is a python3 script designed to take the output from masscan (https://github.com/robertdavidgraham/masscan) and clean it up for automated use by other tools. In its current form, it will take the scan results and output each port to its own list of IPs with the time, range and port number appended to the name of the file. 

The ultimate goal of this tool is to build in support for many other tools so that they can all be kicked off from a single command.

###Usage

Run from the command line using the following syntax:

python3 omnislash.py -t 192.168.1.0/24 -p 21,22,137 -o output -a

Options:

-h --help	        -print help file

-t --target	      -target network

-p --port         -ports to scan (need to be comma seperated)

-o --output	      -output file location (do not give it a file type)

-e --enum4linux	  -run the enum4linux plugin

-s --showmount	  -run the showmount plugin

-n --nikto   	    -run the nikto plugin

-a --all 	        -run all tool plugins automatically


###Supported tools

The tools currently supported for automation by Omnislash are as follows:

-nikto (https://github.com/sullo/nikto)

-enum4linux (https://github.com/portcullislabs/enum4linux)

-showmount (http://packages.ubuntu.com/precise/net/nfs-common)


###To do

-Continue adding support for more tools/ports

-Configure plugins to take arguments for port results to scan against (allow for more useability)

###Disclaimer

I did not write any of the tools used by Omnislash and do not take credit for doing so. Omnislash is just meant to make using these tools easier with a single kick-off point for automation.

It has been provided for testing and academic purposes only. Do not use this tool against networks that you do not own or have express/strict written consent to test against. Do not use for illegal purposes.
