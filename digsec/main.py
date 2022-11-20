# coding: utf-8
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name
"""
handles main entry point
"""
import sys
from digsec import enable_debug, dprint, DIGSEC_VERSION, DigsecError
from digsec.help import display_help, display_help_query
from digsec.help import display_help_validate, display_help_download
from digsec.help import display_help_view
from digsec.query import do_query
from digsec.download import do_download
from digsec.validate import do_validate
from digsec.view import do_view
from digsec.utils import has_flag


# pylint: disable=too-many-branches
def main():
    print('digsec v%s' % DIGSEC_VERSION)
    try:
        if has_flag('+debug'):
            enable_debug()
            dprint('Debug mode enabled.')
        if len(sys.argv) < 2:
            display_help()
        else:
            cmd = sys.argv[1]
            show_help = has_flag('+help')
            dprint('cmd: %s' % cmd)
            if cmd == 'query':
                if show_help:
                    display_help_query()
                else:
                    do_query(sys.argv[2:])
            elif cmd == 'download':
                if show_help:
                    display_help_download()
                else:
                    do_download(sys.argv[2:])
            elif cmd == 'validate':
                if show_help:
                    display_help_validate()
                else:
                    do_validate(sys.argv[2:])
            elif cmd == 'view':
                if show_help:
                    display_help_view()
                else:
                    do_view(sys.argv[2:])
            else:
                display_help()
    except DigsecError as e:
        print('ERROR: %s' % e.msg)
        sys.exit(1)
