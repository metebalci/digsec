# coding: utf-8
# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring
import os
import sys


DIGSEC_VERSION = '0.8.1'
__DEBUG = False


def enable_debug():
    # pylint: disable=global-statement
    global __DEBUG
    __DEBUG = True


def dprint(*args):
    if __DEBUG:
        print('DEBUG: ', end='')
        print(*args)


def error(msg):
    print('Error: %s' % msg)
    sys.exit(1)


def ensure_file_exists(filename):
    if not os.path.isfile(filename):
        error('file does not exist: %s' % filename)
