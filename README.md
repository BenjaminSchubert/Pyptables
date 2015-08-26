Pyptables
=========

Pyptables is a python module to simplify the creation and maintenance of iptables rules.

Even though it was made to be quite flexible, it won't be able to handle all cases. If you have problems where Pyptables doesn't fit your needs, but you still want to use it, feel free to open an issue or contribute !

Installation
============

You can install Pyptables with pip:

    pip install pyptables

Usage
=====

Pyptables can either be called directly from the command line as

    $ pyptables

or as a python module such as

    $ python3 -m pyptables

Pyptables can generate a default configuration file for you

    $ pyptables --new-config

By default, Pyptables will look at /etc/pyptables.conf, but you can specify any file with
    pyptables --conf ${PATH_TO_FILE}

For more options, please see `pyptables --help`


Configuration
=============

To configure pyptables, you need an ini-formatted file, by default `/etc/pyptables.conf`

For an example of configuration, please see docs/sample_conf.conf.

The format is as defined like that:

    [DEFAULT]  # default section, contains value that will be used in all others sections if not redefined
    option = value

    [global]  # defines general behavior of iptables
    closed_chains = INPUT,FORWARD # comma-separated list of chains to be closed
    allow_established_traffic = True  # whether or not to allow traffic that has already been validated (ctstate ESTABLISHED,RELATED)
    allow_traffic_on_interface = lo  # interfaces on which to allow traffic unconditionally
    drop_invalid_traffic = True  # whether or not to drop traffic that is invalid. You most certainly want this
    ssh_knocking = True  # whether or not you want a pure iptables-based port knocking solution for ssh
    
    [logging]  # configure the logging of packets before dropping them. If this section does not exist, will simply and silently drop traffic
    rate = 2/sec  # rate limiting for traffic logging in order not to flood dmesg
    level = 4  # the severity level to use when logging
    prefix = Iptables blocked :  # a prefix to add in front of the drop entry in dmesg
    log = INPUT,FORWARD  # the chains for which to enable logging
    ignore_* = #  allows the definition of packets to not log when dropped. This should be named as ignore_${NAME_OF_CHAIN}.
        Netbios NS, eth0, udp, 10.0.0.150, 10.0.0.12, 137, 137;  # these define the name, interface, protocol, source, destination, source_port, destination_port
        Dropbox,, udp,, 17500,,;  # for which not to log. Any entry can be void, and the filter won't look at it if so.
    
    [ssh_knocking]  # this session handles ssh knocking if desired
    ports = 7777,8888,9999 # the port sequence to knock. Can be arbitrarily long
    ssh_port = 22  # the real ssh port to open after a successful sequence
    interface = eth0  # the interface on which to enable ssh knocking
    timeout = 30  # the timeout to let the user connect
    
    [Service Name]  # this is used to add an arbitrary run an iptables command. The ${Service Name} will be used as name in the comments
    chain =  # define the chain in which to enable the command
    action =  # the action to have (DROP; ACCEPT; etc)
    protocol =  # to restrain the rule to a specific protocol
    dport =  # the destination port 
    sport =  # the source port
    source =  # a comma-separated list of ip sources
    destination =  # a comma-separated list of ip destinations
    remote =  # used to specify a hostname for the given ips, when a fully qualified domain name is not what you want
    interface =  # the interface on which to apply the rule
   

The last section can be repeated as much as you wish to enable new rules

