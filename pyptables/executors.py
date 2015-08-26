#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Defines several helpers to add rules to Iptables
"""

from configparser import SectionProxy
from contextlib import suppress
from ipaddress import ip_address, ip_network
import re
import socket

from pyptables.iptables import Iptables, Ip6tables, IptablesRule

__author__ = 'Benjamin Schubert, ben.c.schubert@gmail.com'


ipv4_handler = Iptables()
ipv6_handler = Ip6tables()


def get_ip_address(name: str):
    """
    Tries to convert the input to an ip address
    :param name: the input to convert
    :return: the correct ip address or None if unable to convert
    """
    with suppress(ValueError):
        return ip_address(name)
    with suppress(ValueError):
        return ip_network(name)
    with suppress(socket.gaierror, ValueError):
        return ip_address(socket.gethostbyname(name))

    return None


def setup_global_begin(config: SectionProxy) -> None:
    """
    Sets up the tables globally for ipv4 and ipv6

    :param config: the configuration used
    """
    # noinspection PyUnresolvedReferences
    def setup(handler: Iptables, _config: SectionProxy) -> None:
        """
        Sets up the tables to accept new rules : resets all rules, set defaults and allow global traffic

        :param handler: the Iptables instance on which to operate
        :param _config: the configuration used
        """
        handler.reset()
        for chain in _config.getlist("closed_chains", []):
            handler.set_default(chain, "DROP")

        if _config.getboolean("allow_established_traffic", False):
            handler.allow_existing_traffic()

        for interface in _config.getlist("allow_traffic_on_interface", []):
            handler.allow_traffic_on_interface(interface)

        if _config.getboolean("drop_invalid_traffic", False):
            handler.drop_invalid_traffic()

    if config.getboolean("ipv4", False):
        setup(ipv4_handler, config)

    if config.getboolean("ipv6", False):
        setup(ipv6_handler, config)


def setup_global_end(config: SectionProxy) -> None:
    """
    Sets up the last things : logging, drops and ssh knocking

    :param config: the config to use
    """
    def setup(handler: Iptables, _config: SectionProxy, version) -> None:
        """
        Ties up the settings : logging, drops and ssh knocking

        :param handler: the Iptables instance on which to operate
        :param _config: the configuration used
        :param version: the version of ip protocol used (4 or 6)
        """
        if _config.parser.has_section("logging"):
            for entry in _config.parser.items("logging"):
                if not entry[0].startswith("ignore_"):
                    continue

                chain = entry[0].replace("ignore_", "").upper()
                values = [item for item in re.split(r";\s*", entry[1]) if item != ""]

                for value in values:
                    data = [item if item != "" else None for item in re.split(r",\s*", value.strip())]
                    address1, address2 = data[4:6]
                    if address1 is not None:
                        address1 = get_ip_address(address1)
                    if address2 is not None:
                        address2 = get_ip_address(address2)

                    if (address1 is not None and address1.version != version) or (
                            address2 is not None and address2.version != version):
                        continue

                    handler.no_log(chain, *data)

        if _config.getboolean("ssh_knocking"):
            handler.enable_ssh_knocking(_config.parser["ssh_knocking"])

        if _config.parser.has_section("logging"):
            section = _config.parser["logging"]
            for chain in section.getlist("log"):
                handler.log(chain, section.get("prefix"), section.get("rate", None), section.getint("level", 4))

    if config.getboolean("ipv4", False):
        setup(ipv4_handler, config, version=4)

    if config.getboolean("ipv6", False):
        setup(ipv6_handler, config, version=6)


# noinspection PyUnresolvedReferences
def handle_service(config: SectionProxy) -> None:
    """
    Sets a rule or a service

    :param config: the configuration for the rule
    """
    for src in config.getlist("source", [None]):
        for dst in config.getlist("destination", [None]):
            source = None
            destination = None

            if src is not None:
                source = get_ip_address(src)
                if source is None:
                    print("[ERROR] Could not determine ip address for {} : skipping".format(src))
                    continue

            if dst is not None:
                destination = get_ip_address(dst)
                if destination is None:
                    print("[ERROR] Could not determine ip address for {} : skipping".format(dst))
                    continue

            rule = IptablesRule(
                name=config.name,
                interface=config.get("interface"),
                chain=config.get("chain"),
                protocol=config.get("protocol"),
                action=config.get("action"),
                source=source,
                destination=destination,
                sport=config.get("sport"),
                dport=config.get("dport"),
                remote=config.get("remote", None)
            )

            if config.getboolean("ipv4", False) and (rule.source is None or rule.source.version == 4) and \
                    (rule.destination is None or rule.source.version == 4):
                ipv4_handler.add_rule(rule)
            if config.getboolean("ipv6") and (rule.source is None or rule.source.version == 6) and \
                    (rule.destination is None or rule.source.version == 6):
                ipv6_handler.add_rule(rule)

            if (rule.source is not None and rule.destination is not None) and \
                    rule.destination.version != rule.source.version:
                print("[ERROR] Could not add rule with ip versions no matching: {} and {}".format(
                    str(rule.source, rule.destination)
                ))
