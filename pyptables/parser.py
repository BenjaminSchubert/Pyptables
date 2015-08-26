# -*- coding: utf-8 -*-
# noinspection PyProtectedMember

"""
Adds some improved parser specifically for Pyptables
"""

# noinspection PyProtectedMember
from configparser import ConfigParser, _UNSET, NoSectionError, NoOptionError, SectionProxy
import os
import re


__author__ = 'Benjamin Schubert, ben.c.schubert@gmail.com'


# noinspection PyShadowingBuiltins
def getlist(self, option: str, fallback: list=None, *, raw: bool=False, vars: dict=None) -> list:
    """
    Converts a SectionProxy cvs option to a list
    :param option: the option to get
    :param fallback: default value, if option does not exist
    :param raw: True to disable interpolation
    :param vars: additional substitutions
    :return: a list corresponding to the option
    """
    return self._parser.getlist(self._name, option, raw=raw, vars=vars, fallback=fallback)

SectionProxy.getlist = getlist


class TypedConfigParser(ConfigParser):
    """
    A list-aware Configuration parser
    """
    LIST_SEPARATOR = ","

    @staticmethod
    def _convert_to_list(value: str) -> list:
        """
        Converts a vcs string to a list
        :param value: string to convert
        :return: the corresponding list
        """
        return [item for item in re.split(r"{}\s*".format(TypedConfigParser.LIST_SEPARATOR), value) if item != ""]

    @staticmethod
    def _convert_to_dir(value: str) -> str:
        """
        Sanitizes the string given to expand users and vars for a directory
        :param value: un-sanitized string representing the directory
        :return: str : the sanitized string
        """
        return os.path.expanduser(os.path.expandvars(value))

    # noinspection PyShadowingBuiltins
    def getlist(self, section: str, option, *, raw: bool=False, vars=None, fallback=_UNSET) -> list:
        """
        Return a list value for the named option in the named section
        :param section: the section to search
        :param option: the wanted option
        :param raw: if True, will not interpolate values
        :param vars: additional substitutions
        :param fallback: fallback value
        :return: the given option as a list
        """
        try:
            return self._get(section, self._convert_to_list, option, raw=raw, vars=vars)
        except (NoSectionError, NoOptionError):
            if fallback is _UNSET:
                raise
            else:
                return fallback
