#! python3
# massNikto.py - v1.0
# Author- David Sullivan
#
# Runs masscan against its target list and automatically runs the results against nikto
#
# Revision  1.0     -   02/14/2018- Initial creation of script

# To do:
#   -   does not support port ranges other than pre-defined ranges, otherwise you need to specify comma-delimited ports


import getopt, os, sys, datetime

# globals
ports = ''
target = ''
output = ''
time = (str(datetime.datetime.now()).split(' ')[0])
all_ports = list(range(0, 65536))
well_known_ports = list(range(0, 1024))


def usage():
    print('massNikto- python3')
    print()
    print('Usage: python3 massNikto.py -t 192.168.1.0/24 -p 80,443,8080 -o output')
    print('-------------------------------------------------------------------------')
    print('-t   --target        -target network')
    print('-p   --port          -ports to scan (need to be comma separated)')
    print('-p   --port          -p all or --port all will scan for all ports')
    print('-p   --port          -p wk or --port wk will scan ports 0-1023')
    print('-o   --output        -output file location (do not give it a file type)')
    print('-h   --help          -print this help file')
    print('-------------------------------------------------------------------------')
    print('***Requires MassScan and Nikto to be installed***')
    print('-------------------------------------------------------------------------')
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


def nikto(ports, target, output):
    # Build a working list to compare ports against
    nports = list(ports.split(','))

    for iPort in nports:
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


# noinspection PyBroadException
def main():
    global ports, target, output, opts, all_ports, well_known_ports

    # if no arguments given, run usage
    if not len(sys.argv[1:]):
        usage()

    # read the commandline options
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'h:t:p:o:h',
                                   ['help', 'target', 'port', 'output'])
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
        elif o in ('-o', '--output'):
            output = a
        else:
            assert False, 'Unhandled option'

    # if all or well known ports are selected, create all ports list
    if ports == 'all':
        nports = ','.join(str(x) for x in all_ports)
        ports = '0-65535'
    elif ports == 'wk':
        nports = ','.join(str(x) for x in well_known_ports)
        ports = '0-1023'
    else:
        nports = ports

    # add timestamp and range to output
    if '/' not in target:
        target = target + '/32'
    output = ('%s_%s_%s' % (output, time, ('%s-%s' % ((target.split('/')[0]), (target.split('/')[1])))))

    # call masscan and run Nikto
    masscan(ports, target, output)
    cleanup(nports, target, output)
    nikto(nports, target, output)

    print('Masscan results can be found in %s (with appended port results)' % output)


main()
