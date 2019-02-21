import sys
import os


__DEBUG = False


def enable_debug():
    global __DEBUG
    __DEBUG = True


def dprint(*args):
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
