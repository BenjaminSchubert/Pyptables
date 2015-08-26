#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Default runner for Pyptables
"""

from argparse import ArgumentParser, Namespace
import os
import sys
import subprocess

from pyptables import conf_generator
from pyptables import executors
from pyptables.iptables import Iptables
from pyptables.iptables import Ip6tables
from pyptables.parser import TypedConfigParser

__author__ = 'Benjamin Schubert, ben.c.schubert@gmail.com'


def parse_args(arguments=None) -> Namespace:
    """
    Argument parser for the command line invocation of Pyptables

    :param arguments: the arguments to pass
    :return: Namespace containing the arguments
    """
    _parser = ArgumentParser(description="A wrapper around iptables")
    _parser.add_argument("--new-config", action="store_true")
    _parser.add_argument("--conf", type=str)
    _parser.add_argument("--dry-run", action="store_true")

    args = _parser.parse_args(arguments or sys.argv[1:])

    if args.conf is None:
        args.conf = "/etc/pyptables.conf"

    if os.path.exists(args.conf) and os.path.isfile(args.conf):
        args.conf = os.path.abspath(args.conf)
    elif args.new_config:
        pass
    else:
        print("{} does not exists or is not a file".format(args.conf))
        _parser.print_usage()
        exit(1)

    return args


def generate_iptables(config: TypedConfigParser) -> int:
    """
    Main runner to generate Iptables rules

    :param config: the configuration used to define the rules
    :raise subprocess.CalledProcessError on unexpected error
    :return: 0 on success, -X on error
    """
    if config.has_section("global"):
        try:
            executors.setup_global_begin(config["global"])
        except subprocess.CalledProcessError as exc:
            if exc.returncode == 127:
                print("iptables was not found in your path. This may be caused if you are not running it as root")
                return -1
            else:
                raise

    for section in config.sections():
        if section in ["global", "ssh_knocking", "logging"]:
            continue

        try:
            print(section)
            executors.handle_service(config[section])
        except subprocess.CalledProcessError:
            return -10

    if config.has_section("global"):
        try:
            executors.setup_global_end(config["global"])
        except subprocess.CalledProcessError:
            return -15


def run():
    """
    Parses the configuration, and run the utility

    :return: 0 on success, -X on error
    """
    arguments = parse_args()
    config = TypedConfigParser()
    config.read(arguments.conf)

    if arguments.new_config:
        conf_generator.generate_sample_conf()
        return

    if arguments.dry_run:
        Iptables.execute = lambda s, x: print("Iptables", x)
        Ip6tables.execute = lambda s, x: print("Ip6tables", x)

    try:
        return generate_iptables(config)
    except Exception as exc:
        print("ERROR :", exc)
        return -1
