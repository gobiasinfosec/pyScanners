#! python3
# omnislash.py - v1.0.3
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
#   -realvnc-auth-bypass.nse (https://svn.nmap.org/nmap/scripts/realvnc-auth-bypass.nse)
#   -vnc-info.nse(https://svn.nmap.org/nmap/scripts/vnc-info.nse)
#   -smtp-open-relay.nse(https://svn.nmap.org/nmap/scripts/smtp-open-relay.nse)
#   -mysql-enum.nse(https://svn.nmap.org/nmap/scripts/mysql-enum.nse)
#   -mysql-empty-password.nse(https://svn.nmap.org/nmap/scripts/mysql-empty-password.nse)
#   -ms-sql-info.nse(https://svn.nmap.org/nmap/scripts/ms-sql-info.nse)
#
# Revision  1.0     -   01/25/2017- Initial creation of script
#           1.0.1   -   01/26/2017- Added support for ftp-anon.nse, additional ports for nikto,
#                                   reduced wait time for masscan, 'all' flag to automatically
#                                   scan for all supported ports, vnc-info.nse, realvnc-auth-bypass.nse,
#                                   smtp-open-relay.nse
#           1.0.2   -   01/27/2017- Added support for mysql-enum.nse and mysql-empty-password.nse,
#                                   ms-sql-info.nse
#           1.0.3   -   02/14/2018- Some debugging, got rid of empty files generated, etc.
#
# To do:
#   -   add support for more tools
#   -   configure plugins to take arguments for port results to scan against (overriding
#       defaults will require replacing getopt)
#   -   clean up output so it is less verbose
#   -   work on a timeout for Nikto running against https (hangs pretty bad)
#   -   implement threading
#   -   create separate help file
#   -   combine all ports when running enum4linux and only run against 1 set of IPs (reduces duplication)

import getopt, os, sys, datetime

# globals
ports = ''
target = ''
output = ''
time = (str(datetime.datetime.now()).split(' ')[0])

# plugin globals
all_plugins = False
showmount_plugin = False
enum4linux_plugin = False
nikto_plugin = False
ftpanon_plugin = False
vnc_plugin = False
smtpRelay_plugin = False
mysql_plugin = False
mssql_plugin = False

# global ports
ftpanon_ports = [21]
nikto_ports = [80, 443]
enum4linux_ports = [137, 139, 445]
showmount_ports = [2049]
vnc_ports = [5900]
smtpRelay_ports = [25, 465, 587]
mysql_ports = [3306]
mssql_ports = [445, 1433]
all_ports = [ftpanon_ports, nikto_ports, mysql_ports, enum4linux_ports, showmount_ports, vnc_ports, smtpRelay_ports]


def usage():
    print('Omnislash- python3')
    print()
    print('Usage: python3 omnislash.py -t 192.168.1.0/24 -p 21,22,137 -o output -a')
    print('-------------------------------------------------------------------------')
    print('-t   --target        -target network')
    print('-p   --port          -ports to scan (need to be comma seperated)')
    print('-p   --port          -p all or --port all will scan for all supported ports')
    print('-o   --output        -output file location (do not give it a file type)')
    print('-e   --enum4linux    -run the enum4linux plugin')
    print('-s   --showmount     -run the showmount plugin')
    print('-n   --nikto         -run the nikto plugin')
    print('-f   --ftpanon       -run the ftp-anon.nse plugin')
    print('-m   --mail          -run the smtp-open-relay.nse plugin')
    print('-i   --mssql         -run the ms-sql-info.nse plugin')
    print('-q   --mysql         -run the mysql.nse plugins')
    print('-v   --vnc           -run the vnc.nse scripts plugin')
    print('-a   --all           -run all tool plugins automatically')
    print('-h   --help          -print this help file')
    print('-------------------------------------------------------------------------')
    print('***Requires MassScan to be installed***')
    print('-------------------------------------------------------------------------')
    print('***Additional Tools Needed to Run Plugins:')
    print('***-enum4linux (https://github.com/portcullislabs/enum4linux)')
    print('***-NFS-Common (http://packages.ubuntu.com/precise/net/nfs-common)')
    print('***-Nikto (https://github.com/sullo/nikto)')
    print('***-ftp-anon.nse (https://svn.nmap.org/nmap/scripts/ftp-anon.nse)')
    print('***-realvnc-auth-bypass.nse (https://svn.nmap.org/nmap/scripts/realvnc-auth-bypass.nse)')
    print('***-vnc-info.nse(https://svn.nmap.org/nmap/scripts/vnc-info.nse)')
    print('***-smtp-open-relay.nse(https://svn.nmap.org/nmap/scripts/smtp-open-relay.nse)')
    print('***-mysql-enum.nse(https://svn.nmap.org/nmap/scripts/mysql-enum.nse)')
    print('***-mysql-empty-password.nse(https://svn.nmap.org/nmap/scripts/mysql-empty-password.nse)')
    print('***-ms-sql-info.nse(https://svn.nmap.org/nmap/scripts/ms-sql-info.nse)')
    sys.exit()


def masscan(ports, target, output):
    print('Running masscan against %s using ports %s' % (target, ports))
    arguments = 'masscan -p %s %s --wait=0 > %s' % (ports, target, output)
    os.system(arguments)


def cleanup(ports, target, output):
    oList = []
    newList = []

    # Build a working list to compare ports against
    compareList = ports.split(',')
    for portno in range(len(compareList)):
        compareList[portno] = ('%s/tcp' % compareList[portno])

    f = open(output, 'r')
    print('Cleaning up output')

    # extract the IP address and Port from each line
    for line in f:
        oList.append([(line.split()[3]), (line.split()[-1])])
    f.close()

    # sort the results to different output files based on port
    for portno in compareList:
        for result in range(len(oList)):
            if oList[result][0] == portno:
                newList.append(oList[result][1])

                # remove duplicates and put in numerical order by IP
                newList = list(set(newList))
                newList.sort(key=lambda s: list(map(int, s.split('.'))))

                # save/overwrite file
                out = open(('%s_%s' % (output, (portno.split('/')[0]))), 'w')
                for address in newList:
                    out.write(address + '\n')
                out.close()
                newList = []


def ftpanon(ports, target, output):
    global ftpanon_ports

    for iPort in ftpanon_ports:
        try:
            oList = []
            f = open(('%s_%s' % (output, iPort)), 'r')

            # import each line from the list into a variable
            for line in f:
                oList.append(line.rstrip())
            f.close()

            # run ftp-anon.nse against each argument
            for address in oList:
                print('Running ftp-anon.nse against %s:%s' % (address, iPort))
                arguments = ('nmap -p %s --script ftp-anon %s >> %s 2>&1' % (
                    iPort, address, ('%s_%s_ftp-anon' % (output, iPort))))
                os.system(arguments)

            print('ftp-anon.nse results for port %s can be found in %s_%s_ftp-anon' % (iPort, output, iPort))

        except Exception:
            pass


def smtpRelay(ports, target, output):
    global smtpRelay_ports

    for iPort in smtpRelay_ports:
        try:
            oList = []
            f = open(('%s_%s' % (output, iPort)), 'r')

            # import each line from the list into a variable
            for line in f:
                oList.append(line.rstrip())
            f.close()

            # run smtp-open-relay.nse against each argument
            for address in oList:
                print('Running smtp-open-relay.nse against %s:%s' % (address, iPort))
                arguments = ('nmap -p %s --script smtp-open-relay %s >> %s 2>&1' % (
                    iPort, address, ('%s_%s_smtpRelay' % (output, iPort))))
                os.system(arguments)

            print('smtp-open-relay.nse results for port %s can be found in %s_%s_smtpRelay' % (iPort, output, iPort))

        except Exception:
            pass


def vncCheck(ports, target, output):
    global vnc_ports

    for iPort in vnc_ports:
        try:
            oList = []
            f = open(('%s_%s' % (output, iPort)), 'r')

            # import each line from the list into a variable
            for line in f:
                oList.append(line.rstrip())
            f.close()

            # run vnc.nse scripts against each argument
            for address in oList:
                print('Running vnc.nse scripts against %s:%s' % (address, iPort))
                arguments = ('nmap -p %s --script vnc-info.nse --script realvnc-auth-bypass.nse %s >> %s 2>&1' % (
                    iPort, address, ('%s_%s_vnc' % (output, iPort))))
                os.system(arguments)

            print('vnc.nse results for port %s can be found in %s_%s_vnc' % (iPort, output, iPort))

        except Exception:
            pass


def mysql(ports, target, output):
    global mysql_ports

    for iPort in mysql_ports:
        try:
            oList = []
            f = open(('%s_%s' % (output, iPort)), 'r')

            # import each line from the list into a variable
            for line in f:
                oList.append(line.rstrip())
            f.close()

            # run mysql.nse scripts against each argument
            for address in oList:
                print('Running mysql.nse scripts against %s:%s' % (address, iPort))
                arguments = ('nmap -p %s --script mysql-enum.nse --script mysql-empty-password.nse %s >> %s 2>&1' % (
                    iPort, address, ('%s_%s_mysql' % (output, iPort))))
                os.system(arguments)

            print('mysql.nse results for port %s can be found in %s_%s_mysql' % (iPort, output, iPort))

        except Exception:
            pass


def mssql(ports, target, output):
    global mssql_ports

    for iPort in mssql_ports:
        try:
            oList = []
            f = open(('%s_%s' % (output, iPort)), 'r')

            # import each line from the list into a variable
            for line in f:
                oList.append(line.rstrip())
            f.close()

            # run ms-sql-info.nse script against each argument
            for address in oList:
                print('Running ms-sql-info.nse script against %s:%s' % (address, iPort))
                arguments = ('nmap -p %s --script ms-sql-info.nse %s >> %s 2>&1' % (
                    iPort, address, ('%s_%s_mssql' % (output, iPort))))
                os.system(arguments)

            print('ms-sql-info.nse results for port %s can be found in %s_%s_mssql' % (iPort, output, iPort))

        except Exception:
            pass


def nikto(ports, target, output):
    global nikto_ports

    for iPort in nikto_ports:
        try:
            oList = []
            f = open(('%s_%s' % (output, iPort)), 'r')

            # import each line from the list into a variable
            for line in f:
                oList.append(line.rstrip())
            f.close()

            # run nikto against each argument
            for address in oList:
                print('Running nikto against %s:%s' % (address, iPort))
                arguments = ('nikto -h %s -p %s >> %s 2>&1' % (address, iPort, ('%s_%s_nikto' % (output, iPort))))
                os.system(arguments)

            print('Nikto results for port %s can be found in %s_%s_nikto' % (iPort, output, iPort))

        except Exception:
            pass


def enum4linux(ports, target, output):
    global enum4linux_ports

    for iPort in enum4linux_ports:
        try:
            oList = []
            f = open(('%s_%s' % (output, iPort)), 'r')

            # import each line from the list into a variable
            for line in f:
                oList.append(line.rstrip())
            f.close()

            # run enum4linux against each argument
            for address in oList:
                print('Running enum4linux against %s:%s' % (address, iPort))
                arguments = ('enum4linux %s >> %s 2>&1' % (address, ('%s_%s_enum4linux' % (output, iPort))))
                os.system(arguments)

            print('enum4linux results for port %s can be found in %s_%s_enum4linux' % (iPort, output, iPort))

        except Exception:
            pass


def showmount(ports, target, output):
    global showmount_ports

    for iPort in showmount_ports:
        try:
            oList = []
            f = open(('%s_%s' % (output, iPort)), 'r')

            # import each line from the list into a variable
            for line in f:
                oList.append(line.rstrip())
            f.close()

            # run showmount against each argument
            for address in oList:
                print('Running showmount against %s:%s' % (address, iPort))
                arguments = ('showmount -e %s >> %s 2>&1' % (address, ('%s_%s_showmount' % (output, iPort))))
                os.system(arguments)

            print('showmount results for port %s can be found in %s_%s_showmount' % (iPort, output, iPort))

        except Exception:
            pass


def main():
    global ports, target, output, time, all_plugins, enum4linux_plugin, showmount_plugin
    global vnc_plugin, nikto_plugin, ftpanon_plugin, all_ports, smtpRelay_plugin, mysql_plugin, mssql_plugin

    # if no arguments given, run usage
    if not len(sys.argv[1:]):
        usage()

    # read the commandline options
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'o:p:t:haeqfimnvs',
                                   ['mssql', 'mysql', 'output', 'mail', 'vnc', 'target', 'nikto', 'port', 'ftpanon',
                                    'enum4linux', 'showmount', 'all', 'help'])
    except getopt.GetoptError as err:
        print(str(err))
        usage()

    # handle arguments
    for o, a in opts:
        if o in ('-h', '--help'):
            usage()
        elif o in ('-t', '--target'):
            target = a
        elif o in ('-p', '--port'):
            ports = a
        elif o in ('-a', '--all'):
            all_plugins = True
        elif o in ('-e', '--enum4linux'):
            enum4linux_plugin = True
        elif o in ('-f', '--ftpanon'):
            ftpanon_plugin = True
        elif o in ('-v', '--vnc'):
            vnc_plugin = True
        elif o in ('-m', '--mail'):
            smtpRelay_plugin = True
        elif o in ('-s', '--showmount'):
            showmount_plugin = True
        elif o in ('-n', '--nikto'):
            nikto_plugin = True
        elif o in ('-q', '--mysql'):
            mysql_plugin = True
        elif o in ('-i', '--mssql'):
            mssql_plugin = True
        elif o in ('-o', '--output'):
            output = a
        else:
            assert False, ('Unhandled option')

    # if all ports selected, create all ports list
    if ports == 'all':
        pList = []
        for i in range(len(all_ports)):
            for ii in range(len(all_ports[i])):
                pList.append(str(all_ports[i][ii]))
        ports = ','.join(pList)

    # add timestamp and range to output
    if '/' not in target:
        target = target + '/32'
    output = ('%s_%s_%s' % (output, time, ('%s-%s' % ((target.split('/')[0]), (target.split('/')[1])))))

    # call masscan with options
    masscan(ports, target, output)
    cleanup(ports, target, output)

    if all_plugins:
        ftpanon(ports, target, output)
        nikto(ports, target, output)
        enum4linux(ports, target, output)
        showmount(ports, target, output)
        vncCheck(ports, target, output)
        smtpRelay(ports, target, output)
        mysql(ports, target, output)
        mssql(ports, target, output)
    else:
        if ftpanon_plugin:
            ftpanon(ports, target, output)
        if nikto_plugin:
            nikto(ports, target, output)
        if enum4linux_plugin:
            enum4linux(ports, target, output)
        if showmount_plugin:
            showmount(ports, target, output)
        if vnc_plugin:
            vncCheck(ports, target, output)
        if smtpRelay_plugin:
            smtpRelay(ports, target, output)
        if mysql_plugin:
            mysql(ports, target, output)
        if mssql_plugin:
            mssql(ports, target, output)

    print('Masscan results can be found in %s (with appended port results)' % (output))


main()

