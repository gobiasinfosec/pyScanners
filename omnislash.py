#! python3
# omnislash.py - v1.1
# Author- David Sullivan
#
# Runs masscan against its target list and automatically cleans up the
# the data to a more useable format
#
# The user can then automate other tools from the masscan results
#
# Currently supported automation:
#   -nikto
#   -enum4linux
#   -showmount
#   -ftp-anon.nse (https://svn.nmap.org/nmap/scripts/ftp-anon.nse)
#
# Revision  1.0- 01/25/2017-    Initial creation of script
#           1.1- 01/26/2017-    Added support for ftp-anon.nse, additional ports for nikto,
#                               reduced wait time for masscan, 'all' flag to automatically
#                               scan for all supported ports
#
#
# To do:
#   -   add support for more tools
#   -   configure plugins to take arguments for port results to scan against (overriding
#       defaults will require replacing getopt)
#   -   clean up output so it is less verbose
#   -   work on a timeout for nikto running against https (hangs pretty bad)
#   -   implement threading
#   -   combine all ports when running enum4linux and only run against 1 set of IPs (reduces duplication)


import getopt, os, sys, datetime

#globals
ports = ''
target = ''
output = ''
all_plugins = False
showmount_plugin = False
enum4linux_plugin = False
nikto_plugin = False
ftpanon_plugin = False
time = (str(datetime.datetime.now()).split(' ')[0])

#global ports
ftpanon_ports = [21]
nikto_ports = [80,443]
enum4linux_ports = [137,139,445]
showmount_ports = [2049]
all_ports = [ftpanon_ports,nikto_ports,enum4linux_ports,showmount_ports]

def usage():
    print('Omnislash- python3')
    print()
    print('Usage: python3 omnislash.py -t 192.168.1.0/24 -p 21,22,137 -o output -a')
    print('-------------------------------------------------------------------------')
    print('-t --target	    -target network')
    print('-p --port        -ports to scan (need to be comma seperated)')
    print('-p --port        -p all or --port all will scan for all supported ports')
    print('-o --output	    -output file location (do not give it a file type)')
    print('-e --enum4linux	-run the enum4linux plugin')
    print('-s --showmount	-run the showmount plugin')
    print('-n --nikto   	-run the nikto plugin')
    print('-f --ftpanon   	-run the ftp-anon.nse plugin')
    print('-a --all 	    -run all tool plugins automatically')
    print('-h --help	    -print this help file')
    print('-------------------------------------------------------------------------')
    print('***Requires MassScan to be installed***')
    print('-------------------------------------------------------------------------')
    print('***Additional Tools Needed to Run Plugins:')
    print('***-enum4linux (https://github.com/portcullislabs/enum4linux)')
    print('***-NFS-Common (http://packages.ubuntu.com/precise/net/nfs-common)')
    print('***-Nikto (https://github.com/sullo/nikto)')
    print('***-ftp-anon.nse (https://svn.nmap.org/nmap/scripts/ftp-anon.nse)')
    sys.exit()

def masscan(ports, target, output):
    print('Running masscan against %s using ports %s' % (target, ports))
    arguments = 'masscan -p %s %s --wait=0 > %s' % (ports,target,output)
    os.system(arguments)

def cleanup(ports, target, output):
    oList = []
    newList = []

    #Build a working list to compare ports against
    compareList = ports.split(',')
    for portno in range(len(compareList)):
        compareList[portno] = ('%s/tcp' % compareList[portno])

    f = open(output, 'r')
    print('Cleaning up output')

    #extract the IP address and Port from each line
    for line in f:
        oList.append([(line.split()[3]),(line.split()[-1])])
    f.close()

    #sort the results to different output files based on port
    for portno in compareList:
        for result in range(len(oList)):
            if oList[result][0] == portno:
                newList.append(oList[result][1])

        #remove duplicates and put in numerical order by IP
        newList = list(set(newList))
        newList.sort(key=lambda s: list(map(int, s.split('.'))))

        #save/overwrite file
        out = open(('%s_%s' % (output, (portno.split('/')[0]))), 'w')
        for address in newList:
          out.write(address+'\n')
        out.close()
        newList = []

def ftpanon(ports, target, output):
    global ftpanon_ports

    for iPort in ftpanon_ports:
        try:
            oList = []
            f = open(('%s_%s' % (output,iPort)), 'r')

            # import each line from the list into a variable
            for line in f:
               oList.append(line.rstrip())
            f.close()

            # run ftp-anon.nse against each argument
            for address in oList:
                print('Running ftp-anon.nse against %s:%s' % (address,iPort))
                arguments = ('nmap -p %s --script ftp-anon %s >> %s 2>&1' % (iPort, address, ('%s_%s_ftp-anon' % (output,iPort))))
                os.system(arguments)

            print('ftp-anon.nse results for port %s can be found in %s_%s_ftp-anon' % (iPort,output,iPort))

        except Exception:
            print('%s_%s not found.' % (output,iPort))

def nikto(ports, target, output):
    global nikto_ports

    for iPort in nikto_ports:
        try:
            oList = []
            f = open(('%s_%s' % (output,iPort)), 'r')

            # import each line from the list into a variable
            for line in f:
               oList.append(line.rstrip())
            f.close()

            # run nikto against each argument
            for address in oList:
                print('Running nikto against %s:%s' % (address,iPort))
                arguments = ('nikto -h %s -p %s >> %s 2>&1' % (address, iPort, ('%s_%s_nikto' % (output,iPort))))
                os.system(arguments)

            print('Nikto results for port %s can be found in %s_%s_nikto' % (iPort,output,iPort))

        except Exception:
            print('%s_%s not found.' % (output,iPort))

def enum4linux(ports, target, output):
    global enum4linux_ports

    for iPort in enum4linux_ports:
        try:
            oList = []
            f = open(('%s_%s' % (output,iPort)), 'r')

            #import each line from the list into a variable
            for line in f:
                oList.append(line.rstrip())
            f.close()

            #run enum4linux against each argument
            for address in oList:
                print('Running enum4linux against %s:%s' % (address,iPort))
                arguments = ('enum4linux %s >> %s 2>&1' % (address,('%s_%s_enum4linux' % (output,iPort))))
                os.system(arguments)

            print('enum4linux results for port %s can be found in %s_%s_enum4linux' % (iPort,output,iPort))

        except Exception:
            print('%s_%s not found.' % (output,iPort))

def showmount(ports, target, output):
    global showmount_ports

    for iPort in showmount_ports:
        try:
            oList = []
            f = open(('%s_%s' % (output,iPort)), 'r')

            # import each line from the list into a variable
            for line in f:
                oList.append(line.rstrip())
            f.close()

            # run showmount against each argument
            for address in oList:
                print('Running showmount against %s:%s' % (address,iPort))
                arguments = ('showmount -e %s >> %s 2>&1' % (address, ('%s_%s_showmount' % (output,iPort))))
                os.system(arguments)

            print('showmount results for port %s can be found in %s_%s_showmount' % (iPort,output,iPort))

        except Exception:
            print('%s_%s not found.' % (output,iPort))

def main():
    global ports, target, output, time, all_plugins, enum4linux_plugin, showmount_plugin, nikto_plugin, ftpanon_plugin, all_ports

    #if no arguments given, run usage
    if not len(sys.argv[1:]):
        usage()

    #read the commandline options
    try:
        opts,args = getopt.getopt(sys.argv[1:],'o:p:t:haefns',['output','target','nikto','port','ftpanon','enum4linux','showmount','all','help'])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
	
    #handle arguments
    for o,a in opts:
        if o in ('-h','--help'):
            usage()
        elif o in ('-t','--target'):
            target = a
        elif o in ('-p','--port'):
            ports = a
        elif o in ('-a','--all'):
            all_plugins = True
        elif o in ('-e','--enum4linux'):
            enum4linux_plugin = True
        elif o in ('-f','--ftpanon'):
            ftpanon_plugin = True
        elif o in ('-s','--showmount'):
            showmount_plugin = True
        elif o in ('-n','--nikto'):
            nikto_plugin = True
        elif o in ('-o','--output'):
            output = a
        else:
            assert False, ('Unhandled option')

    #if all ports selected, create all ports list
    if ports == 'all':
        pList = []
        for i in range(len(all_ports)):
            for ii in range(len(all_ports[i])):
                pList.append(str(all_ports[i][ii]))
    ports = ','.join(pList)

    #add timestamp and range to output
    output = ('%s_%s_%s' % (output, time,('%s-%s' % ((target.split('/')[0]),(target.split('/')[1])))))

    #call masscan with options
    masscan(ports, target, output)
    cleanup(ports, target, output)

    if all_plugins == True:
        ftpanon(ports, target, output)
        nikto(ports, target, output)
        enum4linux(ports, target, output)
        showmount(ports, target, output)
    else:
        if ftpanon_plugin == True:
            ftpanon(ports, target, output)
        if nikto_plugin == True:
            nikto(ports, target, output)
        if enum4linux_plugin == True:
            enum4linux(ports, target, output)
        if showmount_plugin == True:
            showmount(ports, target, output)

    print('Masscan results can be found in %s (with appended port results)' % (output))

main()
    print('***Additional Tools Needed to Run Plugins:')
    print('***-enum4linux')
    print('***-NFS-Common')
    print('***-Nikto')
    sys.exit()

def masscan(ports, target, output):
    print('Running masscan against %s' % target)
    arguments = 'masscan -p %s %s > %s' % (ports,target,output)
    os.system(arguments)

def cleanup(ports, target, output):
    oList = []
    newList = []

    #Build a working list to compare ports against
    compareList = ports.split(',')
    for portno in range(len(compareList)):
        compareList[portno] = ('%s/tcp' % compareList[portno])

    f = open(output, 'r')
    print('Cleaning up output')

    #extract the IP address and Port from each line
    for line in f:
        oList.append([(line.split()[3]),(line.split()[-1])])
    f.close()

    #sort the results to different output files based on port
    for portno in compareList:
        for result in range(len(oList)):
            if oList[result][0] == portno:
                newList.append(oList[result][1])

        #remove duplicates and put in numerical order by IP
        newList = list(set(newList))
        newList.sort(key=lambda s: list(map(int, s.split('.'))))

        #save/overwrite file
        out = open(('%s_%s' % (output, (portno.split('/')[0]))), 'w')
        for address in newList:
          out.write(address+'\n')
        out.close()
        newList = []

def nikto(ports, target, output):
    global nikto_ports

    for iPort in nikto_ports:
        try:
            oList = []
            f = open(('%s_%s' % (output,iPort)), 'r')

            # import each line from the list into a variable
            for line in f:
               oList.append(line.rstrip())
            f.close()

            # run nikto against each argument
            for address in oList:
                print('Running nikto against %s:%s' % (address,iPort))
                arguments = ('nikto -h %s >> %s 2>&1' % (address, ('%s_%s_nikto' % (output,iPort))))
                os.system(arguments)

            print('Nikto results for port %s can be found in %s_%s_nikto' % (iPort,output,iPort))

        except Exception:
            print('%s_%s not found.' % (output,iPort))

def enum4linux(ports, target, output):
    global enum4linux_ports

    for iPort in enum4linux_ports:
        try:
            oList = []
            f = open(('%s_%s' % (output,iPort)), 'r')

            #import each line from the list into a variable
            for line in f:
                oList.append(line.rstrip())
            f.close()

            #run enum4linux against each argument
            for address in oList:
                print('Running enum4linux against %s:%s' % (address,iPort))
                arguments = ('enum4linux %s >> %s 2>&1' % (address,('%s_%s_enum4linux' % (output,iPort))))
                os.system(arguments)

            print('enum4linux results for port %s can be found in %s_%s_enum4linux' % (iPort,output,iPort))

        except Exception:
            print('%s_%s not found.' % (output,iPort))

def showmount(ports, target, output):
    global showmount_ports

    for iPort in showmount_ports:
        try:
            oList = []
            f = open(('%s_%s' % (output,iPort)), 'r')

            # import each line from the list into a variable
            for line in f:
                oList.append(line.rstrip())
            f.close()

            # run showmount against each argument
            for address in oList:
                print('Running showmount against %s:%s' % (address,iPort))
                arguments = ('showmount -e %s >> %s 2>&1' % (address, ('%s_%s_showmount' % (output,iPort))))
                os.system(arguments)

            print('showmount results for port %s can be found in %s_%s_showmount' % (iPort,output,iPort))

        except Exception:
            print('%s_%s not found.' % (output,iPort))

def main():
    global ports, target, output, time, all_plugins, enum4linux_plugin, showmount_plugin, nikto_plugin

    #if no arguments given, run usage
    if not len(sys.argv[1:]):
        usage()

    #read the commandline options
    try:
        opts,args = getopt.getopt(sys.argv[1:],'o:p:haenst:o',['output','target','nikto','port','enum4linux','showmount','all','help'])
    except getopt.GetoptError as err:
        print(str(err))
        usage()
	
    #handle arguments
    for o,a in opts:
        if o in ('-h','--help'):
            usage()
        elif o in ('-t','--target'):
            target = a
        elif o in ('-p','--port'):
            ports = a
        elif o in ('-a','--all'):
            all_plugins = True
        elif o in ('-e','--enum4linux'):
            enum4linux_plugin = True
        elif o in ('-s','--showmount'):
            showmount_plugin = True
        elif o in ('-n','--nikto'):
            nikto_plugin = True
        elif o in ('-o','--output'):
            output = a
        else:
            assert False, ('Unhandled option')

    #add timestamp and range to output
    output = ('%s_%s_%s' % (output, time,('%s-%s' % ((target.split('/')[0]),(target.split('/')[1])))))

    #call masscan with options
    masscan(ports, target, output)
    cleanup(ports, target, output)

    if all_plugins == True:
        nikto(ports, target, output)
        enum4linux(ports, target, output)
        showmount(ports, target, output)
    else:
        if nikto_plugin == True:
            nikto(ports, target, output)
        if enum4linux_plugin == True:
            enum4linux(ports, target, output)
        if showmount_plugin == True:
            showmount(ports, target, output)

    print('Masscan results can be found in %s (with appended port results)' % (output))

main()


