# pylint: disable=missing-module-docstring
# pylint: disable=missing-function-docstring
import os
import sys


DIGSEC_VERSION = '0.7.2'
__DEBUG = False


def enable_debug():
    # pylint: disable=global-statement
    global __DEBUG
    __DEBUG = True


def dprint(*args):
    # pylint: disable=global-statement
    global __DEBUG
    if __DEBUG:
        print('DEBUG: ', end='')
        print(*args)


def error(msg):
    print('Error: %s' % msg)
    sys.exit(1)


def ensure_file_exists(filename):
    if not os.path.isfile(filename):
        error('file does not exist: %s' % filename)
