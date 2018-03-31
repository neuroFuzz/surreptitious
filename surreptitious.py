'''
    Author: Andres Andreu < andres at neurofuzzsecurity dot com >
    Company: neuroFuzz, LLC
    Date: 7/21/2016
    Last Modified: 03/29/2018

    BSD 3-Clause License

    Copyright (c) 2016 - 2018, Andres Andreu, neuroFuzz LLC
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation and/or
    other materials provided with the distribution.

    3. Neither the name of the copyright holder nor the names of its contributors may
    be used to endorse or promote products derived from this software without specific
    prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
    EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
    OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
    IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
    INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
    BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
    OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
    OF SUCH DAMAGE.

    *** Take note:
    If you use this for criminal purposes and get caught you are on
    your own and I am not liable. I wrote this for legitimate
    pen-testing and auditing purposes.
    ***

    Be kewl and give credit where it is due if you use this. Also,
    send me feedback as I don't have the bandwidth to test for every
    condition - Dre

'''
import sys
import random
import socket
import signal
import os
import optparse
import glob
import time
import subprocess
import multiprocessing
from struct import *
from libs.nftk_requirements import get_required_paths
from libs.nftk_sys_funcs import delete_file, find_file
from libs import nftk_socket_controller as SocketController
from libs import nftk_modify_proxychains_conf as PrxConf
#####################################################
#ports = [i for i in range(1,65536)]
#ports = [i for i in range(79,85)]
THRESHOLD = 6
TMPFILE = '/tmp/disc_ports_{}'
#USETOR = False
USETOR = True
VERBOSE = True
REMOVE_RESULTS = False
#####################################################
# funcs

def clean_up_tor_socks():
    ''' '''

    if VERBOSE:
        print("Cleaning up tor sockets")
    for fname in glob.glob('tordata/tor*/tor*.pid'):
        the_pid = ''
        with open (fname, "r") as myfile:
            the_pid = int(myfile.read().strip())
        if the_pid:
            try:
                os.kill(the_pid, signal.SIGQUIT)
                if VERBOSE:
                    print("Killing pid: {}".format(the_pid))
            except OSError:
                pass

    SocketController.clean_slate()
    return


def scan_one(the_ip='', the_port=0, t_ix=1, tor_path=''):
    ''' '''

    if the_port > 0:

        the_sock = None
        if USETOR:
            sc = SocketController.SocketController(tor_executable_path=tor_path)
            if sc:
                sc.spawn_socket(t_instance=t_ix)
                the_sock = sc.set_socks_prox()[0]
            #the_sock = spawn_instance(num=t_ix)
            time.sleep(random.randint(1,3))

        if the_sock:
            s = the_sock
        else:
            s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)

        s.setblocking(1)
        s.settimeout(1)

        '''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)

        result = s.connect_ex((the_ip, the_port))

        if(result == 0):
            #print 'Port %d: OPEN' % (the_port,)
            with open(TMPFILE, "a") as myfile:
                myfile.write("%s\n" % the_port)

        s.close()
        '''

        result = s.connect_ex((the_ip, the_port))

        if(result == 0):
            print('Port {}: OPEN'.format(the_port))
            with open(TMPFILE, "a") as myfile:
                myfile.write("%s\n" % the_port)

        s.close()


def main(tor_path='', the_target='', the_ports=[]):
    ''' '''
    global TMPFILE
    target = None
    try:
        target = the_target
        TMPFILE = TMPFILE.format(target)
    except Exception as err:
        print str(err)
        sys.exit(2)

    if target == None:
        print "No ip given, which is a required argument!"
        sys.exit()

    if len(the_ports) == 0:
        print "Need a range of ports"
        sys.exit()
    else:
        ports = the_ports

    delete_file(target_file=TMPFILE)
    delete_file(target_file="proxychains.conf")

    SocketController.clean_slate()

    #global ports
    #print ports
    the_vars = []

    #try:
    while ports:
        #list_of_ports = []
        #print ports.pop(random.randint(0,len(ports)-1))
        '''
            do a little randomizing of the number
            of simultaneous ports we query
        '''
        if len(ports) > THRESHOLD:
            #ceiling = random.randint(1, len(ports)-1)
            ceiling = random.randint(THRESHOLD/2, THRESHOLD)
        elif len(ports) > 1:
            ceiling = random.randint(1, len(ports)-1)
        else:
            ceiling = 1
        #print ceiling

        if ceiling > 1:
            the_vars = []
            for x in range(1, ceiling + 1):
                #list_of_ports.append(str(ports.pop(random.randint(0,len(ports)-1))))

                #the_vars.append('d' + str(x))
                the_port = ports.pop(random.randint(0,len(ports)-1))
                the_vars.append('d' + str(x) + "_" + str(the_port))

        else:
            #list_of_ports.append(str(ports.pop()))

            the_vars = []
            the_port = ports.pop()
            #print the_port
            the_vars.append('d1' + "_" + str(the_port))


        print "LEN: %d" % len(the_vars)
        #print "LEN: %d" % len(list_of_ports)

        if the_vars:
            for v in the_vars:
                #v_ix = int(v[1:])
                v_ix, v_port = v.split('_')
                v_ix = int(v_ix[1:])
                v_port = int(v_port)
                if VERBOSE:
                    print("Scanning: {}, port: {}".format(target,v_port))
                '''
                print v_ix
                print v_port
                '''
                '''
                globals()[v] = multiprocessing.Process(name=scan_one, args=[target,v_port,v_ix,tor_path], target=scan_one)
                globals()[v].daemon = False
                '''
                p = multiprocessing.Process(name=scan_one, args=[target,v_port,v_ix,tor_path], target=scan_one)
                p.start()
                p.join()

            '''
            for v in the_vars:
                print("Processing: {}".format(v))
                globals()[v].start()
                time.sleep(random.randint(1,4))
                globals()[v].join()
                print("Done Processing: {}".format(v))
            '''
            """
            print "sleeping 4"
            time.sleep(4)
            print "done sleeping 4"
            # join em
            print "joining"
            for v in the_vars:
                print v
                globals()[v].join(4)

            print "done joining"
            """

        #print(','.join(list_of_ports))


        if USETOR:
            clean_up_tor_socks()

    #except KeyboardInterrupt:
    #    if USETOR:
    #        clean_up_tor_socks()


def read_tmp_data():
    ''' '''
    disc_ports = []

    if os.path.exists(TMPFILE):
        with open(TMPFILE, "r") as myfile:
            disc_ports = myfile.read().split()
        disc_ports.sort(key=int)

    return disc_ports


def scan_via_nmap(nmap_path='',
                proxychains_path='',
                the_ports='',
                the_target='',
                tor_path='',
                results_path=''):

    #print("{} - {} - {} - {} - {} - {}".format(nmap_path,proxychains_path,tor_path,the_ports,the_target,results_path))
    if nmap_path and proxychains_path and the_ports and the_target and results_path:

        if results_path.endswith("/"):
            results_path = results_path[:-1]
        # TODO - handle this mkdir more elegantly
        if not os.path.exists(results_path):
            os.makedirs(results_path)

        # TODO set up some tor sockets for nmap to use
        list_of_sock_ports = []
        sc = SocketController.SocketController(tor_executable_path=tor_path)
        for i in range(100,105):
            if sc:
                sc.spawn_socket(t_instance=i)
                time.sleep(random.randint(1,3))
        for p in sc.get_port_list():
            the_tuple = ('127.0.0.1',p)
            if the_tuple not in list_of_sock_ports:
                list_of_sock_ports.append(the_tuple)

        PrxConf.neurofuzz_modify_proxychains_conf(t_list=list_of_sock_ports)
        proxychains_conf_path = "{}/{}".format(os.getcwd(),'proxychains.conf')

        '''
            nmap's -O (OS detection) requires root priv
        '''
        if os.getuid() == 0:
            cmd = "{} -f {} {} -Pn -O -sV --version-intensity 5 -oA {}/{} -p {} {}".format(
                            proxychains_path,
                            proxychains_conf_path,
                            nmap_path,
                            results_path,
                            str(int(time.time())) + "_" + the_target,
                            the_ports,
                            the_target)
        else:
            cmd = "{} -f {} {} -Pn -sV --version-intensity 5 -oA {}/{} -p {} {}".format(
                            proxychains_path,
                            proxychains_conf_path,
                            nmap_path,
                            results_path,
                            str(int(time.time())) + "_" + the_target,
                            the_ports,
                            the_target)

        '''
        print("CMD: {}".format(cmd))
        print("CMD: {}".format(cmd.split()))
        '''
        if VERBOSE:
            print("Now attempting to run: {}".format(cmd))

        try:
            subprocess.check_output(cmd.split())
        except:
            pass
        sc.kill_sockets()


def usage():
    print("Usage:\npython surreptitious.py -t ip_address -s 1 -e 65535 -p nmap_results\n\n")
    sys.exit()
#####################################################

if __name__ == "__main__":

    target = None
    start_port = 0
    end_port = 0
    results_path = None

    parser = optparse.OptionParser()
    parser.add_option('-t', action="store", dest=target)
    parser.add_option('-s', action="store", dest="s", type="int")
    parser.add_option('-e', action="store", dest="e", type="int")
    parser.add_option('-p', action="store", dest="p")
    options, args = parser.parse_args()
    '''
    print options
    print args
    '''
    if options.t:
        target = options.t
    else:
        print("\n{}\n".format("Target IP Address required"))
        usage()
        sys.exit()
    if options.s:
        start_port = options.s
    else:
        print("\n{}\n".format("Start port value required"))
        usage()
        sys.exit()
    if options.e:
        end_port = options.e
    else:
        print("\n{}\n".format("End port value required"))
        usage()
        sys.exit()
    if options.p:
        results_path = options.p
    else:
        print("\n{}\n".format("Results path required"))
        usage()
        sys.exit()

    the_ports = []
    if start_port < 1:
        start_port = 1
    if end_port > 65535:
        end_port = 65535
    if end_port < start_port:
        print("\nEnd port cannot be a lower value than the Start port\n\n")
        sys.exit()
    elif end_port == start_port:
        the_ports.append(start_port)
    else:
        the_ports = [i for i in range(start_port,end_port+1)]

    exe_paths = get_required_paths()
    print exe_paths
    if exe_paths.has_key('error_message'):
        print("\n{}\n\n".format(exe_paths['error_message']))
        sys.exit()

    '''
    try:
        target = sys.argv[1]
    except Exception as err:
        print str(err)
        sys.exit(2)
    '''
    if target and len(the_ports) > 0 and results_path:

        main(tor_path=exe_paths['tor_path'], the_target=target, the_ports=the_ports)

        disc_ports = read_tmp_data()
        if disc_ports:
            print "FOUND:"
            for i in disc_ports:
                print i

        scan_via_nmap(nmap_path=exe_paths['nmap_path'],
                        proxychains_path=exe_paths['proxychains_path'],
                        the_ports=','.join(disc_ports),
                        the_target=target,
                        tor_path=exe_paths['tor_path'],
                        results_path=results_path
                        )

        # get rid of the results file
        if REMOVE_RESULTS:
            delete_file(target_file=TMPFILE)

    sys.exit()
