# surreptitious

A surreptitious/stealthy port scanner

History - I wrote this circa 2015 based on an incident at an intelligence agency.
My goal was to show them that a little bit of wisely crafted python could thwart
some of their multi-million dollar expenditures. Their arrogance certainly was
a major inspiration for me to write this. And for the record they were never able
to detect or stop this code :-)

This was written on Linux and has been used/tested on Fedora and Debian/Ubuntu.
I have no plans or time to port/test to/on any different platforms. If you wanna
contribute in this way or any other way let me know:

    andres [at] neurofuzzsecurity dot com

This prog is intended to be used for legal purposes.

This prog is not meant to be run on a LAN as it uses tor sockets to route each
port check via a different internet based path. So the goal is to scan a public
facing entity (server, etc) in a stealthy manner that cannot be detected.


Requirements:

- python (2.x family currently)
- tor
- proxychains4
- nmap
- neurofuzz_toolkit (https://github.com/dre/neurofuzz_toolkit)


Getting Started:

- go to the directory where you checked out the 'surreptitious' project and copy
everything to your working directory
run the following to pull down the 'neurofuzz_toolkit':

    - python get_nf_toolkit.py


Usage:

    python surreptitious.py -t ip_address -s 1 -e 65535 -p nmap_results

    -t = target ip address to be scanned
    -s = start port
    -e = end port
    -p = path/directory where the final nmap results files will be saved
