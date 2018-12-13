import sys


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
