#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Iptables proxies to access basic iptables commands
"""

from configparser import SectionProxy
from contextlib import suppress
import socket
import subprocess


__author__ = 'Benjamin Schubert, ben.c.schubert@gmail.com'


class IptablesRule:
    """
    Container defining an Iptables rule
    """
    def __init__(self, name, chain, action, protocol=None, interface=None, source=None, destination=None, sport=None,
                 dport=None, remote=None):
        if protocol == interface == source == destination == sport == dport is None:
            raise ValueError(
                "Section {}: At least one of protocol, interface, source, destination,"
                "sport, dport must be non null".format(name)
            )
        self.name = name
        self.chain = chain.upper()
        self.action = action.upper()
        self.protocol = protocol
        self.interface = interface
        self.source = source
        self.destination = destination
        self.sport = sport
        self.dport = dport
        self.remote = remote


class Iptables:
    """
    An Iptable proxy for ipv4
    """
    @property
    def command(self) -> str:
        """ The name of the command line to call """
        return "iptables"

    def execute(self, command: str) -> None:
        """
        Executes a command

        :param command: the command to execute
        """
        subprocess.check_call("{} {}".format(self.command, command), shell=True)

    def reset(self) -> None:
        """ Resets all tables to default values """
        for command in [
            "-F", "-X",
            "-t nat -F", "-t nat -X",
            "-t mangle -F", "-t mangle -X",
            "-P INPUT ACCEPT",
            "-P OUTPUT ACCEPT",
            "-P FORWARD ACCEPT"
        ]:
            self.execute(command)

    def set_default(self, chain: str, action: str) -> None:
        """
        Sets default action for given chain

        :param chain: the chain to use
        :param action: the default action
        """
        self.execute("-P {} {}".format(chain, action))

    def allow_existing_traffic(self) -> None:
        """ Allow all already established or related traffic """
        self.execute('-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED'
                     ' -m comment --comment "Allow already authenticated traffic" -j ACCEPT')

    def allow_traffic_on_interface(self, interface: str) -> None:
        """
        Allows all traffic on given interface

        :param interface: the interface to use
        """
        self.execute('-A INPUT -i {} -m comment --comment "Allow traffic on {}" -j ACCEPT'.format(
            interface, interface
        ))

    def drop_invalid_traffic(self) -> None:
        """ Drops all invalid traffic """
        self.execute('-A INPUT -m conntrack --ctstate INVALID -m comment --comment "Drop invalid traffic" -j DROP')

    def add_rule(self, rule: IptablesRule) -> None:
        """
        Formats and adds a iptables rules

        :param rule: the specification of the rule to add
        """
        command = "-A " + rule.chain
        if rule.protocol:
            command += " -m {proto} -p {proto}".format(proto=rule.protocol)

        if rule.interface:
            command += " -i " + rule.interface

        if rule.destination:
            command += " --dst " + str(rule.destination)

        if rule.source:
            command += " --src " + str(rule.source)

        if rule.sport:
            command += " --sport " + rule.sport

        if rule.dport:
            command += " --dport " + rule.dport

        default_hostname = rule.source
        with suppress(socket.herror, socket.gaierror):
            default_hostname = socket.gethostbyaddr(str(default_hostname))[0]

        if rule.chain == "INPUT":
            command += ' -m comment --comment "{action} {hostname} to connect to {service}{interface}"'.format(
                action="Allow" if rule.action == "ACCEPT" else "Disallow",
                hostname="Anyone" if not rule.source else rule.remote if rule.remote is not None
                else default_hostname,
                service=rule.name,
                interface=" on {}".format(rule.interface) if rule.interface else ""
            )
        elif rule.chain == "OUTPUT":
            command += ' -m comment --comment "{action} to connect to {service} on {hostname}{interface}"'.format(
                action="Allow" if rule.action == "ACCEPT" else "Disallow",
                hostname="Anyone" if not rule.destination else rule.remote if rule.remote is not None
                else socket.gethostbyaddr(str(rule.destination))[0],
                service=rule.name,
                interface=" on {}".format(rule.interface) if rule.interface else ""
            )
        else:
            print("[ERROR] Could not generate help message automatically for {}".format(command + " -j " + rule.action))

        command += " -j " + rule.action

        self.execute(command)

    def enable_ssh_knocking(self, config: SectionProxy) -> None:
        """
        enables iptables-only ssh knocking

        :param config: the configuration to use for the knocking
        """
        def allow_ssh_temporarily(_config: SectionProxy) -> None:
            """
            Allows ssh temporarily

            :param _config: the config to use
            """
            number_of_required_chains = len(_config.getlist("ports"))

            for i in range(1, number_of_required_chains):
                self.execute("-N SSH-KNOCKING-{}".format(i))

            command = "-A INPUT -m state --state NEW -m tcp -p tcp"

            if _config.get("interface", None):
                command += " -i " + _config.get("interface")

            command += " --dport " + _config.get("ssh_port", "22")
            command += " -m recent --rcheck --seconds " + _config.get("timeout", 30)
            command += " --name SSH{}".format(len(_config.getlist("ports")) - 1)
            command += \
                ' -m comment --comment "Allow port {} for ssh for {} if the connecting ip is in the list SSH{}"'.format(
                    _config.get("ssh_port", "22"), _config.get("timeout", 30), len(_config.getlist("ports")) - 1
                )

            self.execute(command)

        def remove_from_list(entry_number: int) -> None:
            """
            Removes the ip from the list given by the number

            :param entry_number: the number for which to remove the list
            """
            command = "-A INPUT -m state --state NEW -m tcp -p tcp -m recent --name SSH{} --remove".format(entry_number)
            command += ' -j DROP -m comment --comment "Remove connecting ip from the SSH{} list"'.format(entry_number)
            self.execute(command)

        def enable_jump(_port: int, entry_number: int) -> None:
            """
            Enables jumping to the given chain

            :param _port: the port on which to enable the jump
            :param entry_number: the number of the entry to which to jump
            """
            command = "-A INPUT -m state --state NEW -m tcp -p tcp --dport {} -m recent --rcheck --name SSH{}".format(
                _port, entry_number - 1
            )
            command += ' -j SSH-KNOCKING-{} -m comment --comment "Checks for the sequence and jumps if correct"'.format(
                entry_number
            )

            self.execute(command)

        def initiate_knocking(_port: int) -> None:
            """
            Sequence initiation for the port knocking

            :param _port: the port on which to knock
            """
            command = "-A INPUT -m state --state NEW -m tcp -p tcp --dport {} -m recent --name SSH0 --set".format(_port)
            command += ' -j DROP -m comment --comment "Sequence initiation for port knocking"'
            self.execute(command)

        def hide_port(number: int) -> None:
            """
            Hides the port given by the number by dropping it

            :param number: the number of the chain on which to drop
            """
            command = "-A INPUT -m recent --name SSH{} --set -j DROP -m comment".format(number)
            command += '--comment "Disguise successful knock as a closed port for obfuscation"'

            self.execute(command)

        # noinspection PyTypeChecker
        allow_ssh_temporarily(config)

        # noinspection PyUnresolvedReferences
        ports = config.getlist("ports")
        for port in reversed(ports):
            remove_from_list(ports.index(port))
            if ports.index(port) != 0:
                enable_jump(port, ports.index(port))
            else:
                initiate_knocking(port)

        for entry in range(len(ports) - 1):
            hide_port(entry)

    def no_log(self, chain, service, interface=None, proto=None, source=None, destination=None, sport=None, dport=None):
        """
        Creates an entry to not log the given chain

        :param chain: INPUT/FORWARD/OUTPUT/others
        :param service: name of the service
        :param interface: network interfaces
        :param proto: protocol used
        :param source: sources ip address/network
        :param destination: destination ip addresses7network
        :param sport: source port
        :param dport: destination port
        """
        command = "-A " + chain

        if interface is not None:
            command += " -i " + interface

        if proto is not None:
            command += " -m {proto} -p {proto}".format(proto=proto)

        if source is not None:
            command += " --src " + source

        if destination is not None:
            command += " --dst " + destination

        if sport is not None:
            command += " --sport " + sport

        if dport is not None:
            command += " --dport " + dport

        if service is not None:
            command += ' -m comment --comment "Drop {} before logging"'.format(service)

        self.execute(command)

    def log(self, chain: str, prefix: str=None, rate: str=None, level: int=None) -> None:
        """
        Logs the given chain

        :param chain: the chain to log
        :param prefix: added in front of the messages to read in dmesg
        :param rate: rate limiting for logging
        :param level: log level to be used
        """
        command = "-A " + chain
        command += ' -m comment --comment "Log remaining traffic" -j LOG'

        if prefix is not None:
            command += ' --log-prefix "{}"'.format(prefix)

        if level is not None:
            command += " --log-level " + str(level)

        if rate is not None:
            command += " -m limit --limit " + rate

        self.execute(command)


class Ip6tables(Iptables):
    """
    An Iptables proxy for ipv6
    """
    @property
    def command(self) -> str:
        """ the command to run for ipv6 """
        return "ip6tables"

    def reset(self) -> None:
        """ the commands to run for ipv6 on reset"""
        for command in [
            "-F", "-X",
            "-t mangle -F", "-t mangle -X",
            "-P INPUT ACCEPT",
            "-P OUTPUT ACCEPT",
            "-P FORWARD ACCEPT"
        ]:
            self.execute(command)
