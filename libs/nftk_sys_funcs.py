"""
    Author: Andres Andreu < andres at neurofuzzsecurity dot com >
    Company: neuroFuzz, LLC
    Date: 10/11/2012
    Last Modified: 08/01/2018

    generic functions that operate at a system level

    BSD 3-Clause License

    Copyright (c) 2012-2020, Andres Andreu, neuroFuzz LLC
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
"""
import sys
import os
import re
import fnmatch
import socket
import itertools
import logging
import platform
import ipaddress


def get_lock(process_name='', process_description=''):
    ''' Sets domain socket as locking mechanism for named process '''
    if not process_description:
        process_description = process_name
    global lock_socket   # Without this our lock gets garbage collected
    lock_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        lock_socket.bind('\0' + process_name)
        return True
    except socket.error:
        logging.info("process '%s' - error acquiring lock" % process_description)
        return False
    except Exception:
        return False


def get_python_version():
    ''' Finds the version of python in use '''
    return platform.python_version()


def which(program=""):
    ''' Finds location (path) of executable code '''
    def is_exe(fpath):
        return os.path.exists(fpath) and os.access(fpath, os.X_OK)

    def ext_candidates(fpath):
        yield fpath
        for ext in os.environ.get("PATHEXT", "").split(os.pathsep):
            yield fpath + ext

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        tarr = os.environ["PATH"].split(os.pathsep)
        '''
            append to 'tarr' as needed if you discover that this
            code doesn't find stuff on your systems. And if it is
            generic enough (meaning not only relevant to your
            system) please get that data back to me so that we
            can all benefit from it.
        '''
        if "/sbin" not in tarr:
            tarr.append("/sbin")
        if "./" not in tarr:
            tarr.append("./")

        for path in tarr:
            exe_file = os.path.join(path, program)
            for candidate in ext_candidates(exe_file):
                if is_exe(candidate):
                    return candidate
    return None


def find_file(filename='', top="/"):
    ''' Walk the path and look for 'filename' '''
    for path, dirlist, filelist in os.walk(top):
        for name in fnmatch.filter(filelist, filename):
            return os.path.join(path, name)
    return None


def find_files_by_pattern(treeroot, pattern):
    ''' Walk the path and look for hits based on the pattern provided '''
    results = []
    for base, dirs, files in os.walk(treeroot):
        goodfiles = fnmatch.filter(files, pattern)
        results.extend(os.path.join(base, f) for f in goodfiles)
    return results


def get_os_string():
    ''' Finds the linux distribution in use '''
    return platform.linux_distribution()[0]


def get_local_ip():
    ''' return the ip address of the system running code that uses this lib '''
    ifconfig_prog = None
    ifconfig_prog = which(program='ifconfig')

    if ifconfig_prog:
        f = os.popen(ifconfig_prog)
        for iface in [' '.join(i) for i in iter(lambda: list(itertools.takewhile(lambda l: not l.isspace(),f)), [])]:
            #print iface
            #print re.findall('(eth|wlan|en)[0-9]',iface)
            if re.findall('(eth|wlan|en*|wl*)[0-9]',iface) and re.findall('RUNNING',iface):
                ip = re.findall('(?<=inet\saddr:)[0-9\.]+',iface)
                if not ip:
                    ip = re.findall('(?<=inet\s)[0-9\.]+',iface)
                #print ip
                if ip:
                    '''
                        TODO - this needs work ... as I have made
                        some assumptions

                        maybe let the user choose the source ip?
                        maybe add some intelligence here ...
                    '''
                    if ip[0].startswith('127'):
                        ip.pop(0)
                    return ip[0]
    return False


def target_ip_private(ip_addr=''):
    ''' returns bool stating whether or not the ip address passed in is private/non-routable '''
    ret = False
    if ip_addr:
        try:
            ret = ipaddress.ip_address(ip_addr.decode('utf-8')).is_private
        except AttributeError:
            ret = ipaddress.ip_address(ip_addr).is_private
    return ret


def delete_file(target_file=''):
    ''' '''
    if target_file:
        if os.path.exists(target_file):
            os.remove(target_file)


def check_dir_exists(the_dir=''):
    ''' '''
    if the_dir:
        if not os.path.exists(the_dir):
            os.makedirs(the_dir)


def is_a_file(fpath=''):
    ''' '''
    ret = False
    if fpath and '\\' not in fpath:
        if os.path.isfile(fpath):
            ret = True
    return ret


def check_dir_exists(the_dir=''):
    ''' '''
    if the_dir:
        if not os.path.exists(the_dir):
            os.makedirs(the_dir)


def get_range_in_subnet(the_subnet=''):
    ''' '''
    if the_subnet:
        return ipaddress.ip_network(the_subnet).hosts()
