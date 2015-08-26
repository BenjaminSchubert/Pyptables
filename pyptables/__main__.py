#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Allows Pyptables to be run as a python module
"""

import sys


__author__ = "Benjamin Schubert, ben.c.schubert@gmail.com"


if sys.argv[0].endswith("__main__.py"):
    sys.argv[0] = "pyptables"


if __name__ == '__main__':
    from pyptables import run
    exit(-(run() or 0))
