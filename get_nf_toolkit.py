"""
    Author: Andres Andreu < andres at neurofuzzsecurity dot com >
    Company: neuroFuzz, LLC
    Date: 02/11/2016
    Last Modified: 09/11/2016

    Prog to fetch and setup the neurofuzz_toolkit

    BSD 3-Clause License

    Copyright (c) 2016 - 2017, Andres Andreu, neuroFuzz LLC
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
    purposes.
    ***
"""
import errno
import os
import random
import string
import urllib2
import zipfile
import ssl

context = ssl._create_unverified_context()

####################################################
NEEDED_DIRS = ['libs', 'vars', 'tordata']
TOOLKIT_URL = 'https://github.com/dre/neurofuzz_toolkit/archive/master.zip'
NF_TK_ZIP = "neurofuzz_toolkit.zip"
INIT_FILE = '__init__.py'
####################################################
def generate_rand_crap(length=0):
    ''' '''
    if length:
        chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
        return ''.join(random.SystemRandom().choice(chars) for _ in range(length))


def file_shred(file_name='', num_passes=7):
    ''' '''
    if not os.path.isfile(file_name):
        print("%s is not a file..." % file_name)
        return False

    ld = os.path.getsize(file_name)
    fh = open(file_name,  "w")
    for _ in range(num_passes):
        rand_dat = generate_rand_crap(length=ld)
        # overwrite file contents
        fh.write(rand_dat)
        fh.seek(0, 0)
    fh.close()
    os.remove(file_name)


def mkdir_p(path=''):
    ''' '''
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def get_raw_filename(t_path=''):
    ''' '''
    if t_path and not t_path.endswith('/'):
        t_path_s = t_path.split('/')
        return t_path_s[len(t_path_s)-1]
    return None
####################################################
# mkdir's if they dont exist
for nd in NEEDED_DIRS:
    mkdir_p(path=nd)

# get zip file
f = urllib2.urlopen(TOOLKIT_URL, context=context)
data = f.read()
# write data out to zip file
with open(NF_TK_ZIP, "wb") as nf_tk:
    nf_tk.write(data)

zFile = zipfile.ZipFile(NF_TK_ZIP)
for zf in zFile.namelist():
    #print zf
    target_dir = ''
    if 'libs/' in zf:
        target_dir = 'libs/'
    elif 'vars/' in zf:
        target_dir = 'vars/'
    elif 'tordata/' in zf:
        target_dir = 'tordata/'

    target_file = get_raw_filename(t_path=zf)

    if target_file:

        target_path = target_dir + target_file
        # ignore init file if it already exists
        if target_file == INIT_FILE:
            if os.path.isfile(target_path):
                #print "Skipping: %s" % target_path
                continue
            else:
                '''
                    just touch the init file since
                    we just have them as empty files
                '''
                open(target_path, 'w').close()
        else:
            #print target_path
            try:
                data = zFile.read(zf)
                with open(target_path, 'wb') as tp:
                    tp.write(data)
            except KeyError:
                print 'ERROR: Did not find %s in zip file' % zf
####################################################
# get rid of toolkit zip file
if os.path.isfile(NF_TK_ZIP):
    file_shred(file_name=NF_TK_ZIP)
