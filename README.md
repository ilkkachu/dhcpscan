# README #

dhcpscan - a simple DHCP scanner for Linux

Copyright (c) 2016-2022 Ilkka Virta <itvirta@iki.fi>

Note: even though the github repo was made in 2022, the software is older,
and while it has been in use and running, it's not tested on recent systems
or distributions. YMMV.

## Background ##

In a network where users can plug in arbitrary devices and wireless home
routers are common, a possible problem comes from routers plugged in the
wrong way, serving DHCP to the network.  Enterprise switches should be able
to filter unauthenticated DHCP replies, but e.g.  not all HPE/Procurve
devices do that.  Luckily, DHCP servers can be scanned for.

I tried to use
[dhcp_probe](https://www.net.princeton.edu/software/dhcp_probe/) at some
point, but didn't get it to work properly on Linux, it missed some reply
packets.  But doing the basic scanning shouldn't be that hard, so `dhcpscan`
was implemented.  It's not as featureful as `dhcp_probe`, but runs nicely
from a cron job, and does what I needed.

## Installation ##

Install libpcap and libnet, download the code and run make or compile with:

    gcc -Wall -O2 -std=c99 -o dhcpscan dhcpscan.c -lpcap -lnet

On Debian (jessie), the libraries are in packages
[libpcap0.8-dev](https://packages.debian.org/jessie/libpcap0.8-dev) and
[libnet1-dev](https://packages.debian.org/jessie/libnet1-dev).


## Example run ##

Example run in verbose mode, finding a server at 192.168.32.1.

    # ./dhcpscan -v -t10 -i eth0
    Opening pcap on interface eth0
    Running as root, dropping privileges
    Sending DHCP query on eth0 (00:50:56:11:22:33)
    Listening for replies on iface eth0 for 10 secs
    [2016-11-08 19:04:05] Got BOOTP reply on eth0 from ether src 00:08:aa:bb:cc:dd IP src 192.168.32.1 with yiaddr 192.168.35.249

Use `dhcpscan -h` to show the help on command line options.

## Copying ##

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License version 2 as published by
 the Free Software Foundation.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
   
 The full text of the license is available in the file `gpl-2.0.txt` in this
 repository and at the [GNU website](https://www.gnu.org/licenses/gpl-2.0.txt).
 The SHA-256 hash of the license text is

    8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643  gpl-2.0.txt

