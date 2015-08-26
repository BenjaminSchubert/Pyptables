#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This module contains a generator for a default pyptables configuration
"""

__author__ = 'Benjamin Schubert, ben.c.schubert@gmail.com'


def generate_sample_conf() -> None:
    """
    Generates a sample configuration for Pyptables and prints it if path is None, else writes it to the file given by
    path
    """
    configuration = """[DEFAULT]
chain = INPUT
action = ACCEPT
ipv4 = True
ipv6 = True

[global]
closed_chains = INPUT, FORWARD
allow_established_traffic = True
allow_traffic_on_interface = lo
drop_invalid_traffic = True
ssh_knocking = False

[logging]
rate = 2/sec
level = 4
prefix = Iptables blocked :
log = INPUT,FORWARD

# the format is : "Service Name, interface, protocol, source, destination, source port, destination port"
# any field can be void, but the "," must be there for each.
# you can use any chain name, as long as it is a valid iptables chain name, like ignore_NAT, ignore_OUTPUT, etc
ignore_INPUT =
    Netbios NS, eth0, udp, 10.0.0.150, 10.0.0.12, 137, 137;
    Dropbox,, udp,,, 17500, 17500;


[ssh_knocking] # this won't be used unless you change in [global] ssh_knocking to True
ports = 777,888,999
ssh_port = 22
interface = eth0
timeout = 30

# and ssh, just in case
[ssh]
protocol = tcp
dport = 22

# This is an example configuration to allow syncthing (a file syncing tool) on your lan

#[syncthing]
#protocol = tcp
#dport = 22000
#interface = eth0
#source = 10.0.0.1/24
#remote = lan"""

    print(configuration)
