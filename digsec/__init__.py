# coding: utf-8
# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring
import os
import sys


DIGSEC_VERSION = '0.9'
__DEBUG = False


def enable_debug():
    # pylint: disable=global-statement
    global __DEBUG
    __DEBUG = True


def dprint(*args):
    if __DEBUG:
        print('DEBUG: ', end='')
        print(*args)


class DigsecError(Exception):
    """Errors"""

    def __init__(self, msg=None):
        super().__init__()
        self.msg = msg
