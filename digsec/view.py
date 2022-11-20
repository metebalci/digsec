# coding: utf-8
# pylint: disable=invalid-name
"""
handles validate command
"""
from digsec import dprint, DigsecError
from digsec.help import display_help_view
from digsec.utils import parse_flags, ensure_file_exists
from digsec.answer import print_answer_file


def do_view(argv):
    """Run view command."""
    if len(argv) < 1:
        display_help_view()
    non_plus = list(filter(lambda x: x[0] != '+', argv))
    dprint(non_plus)
    if len(non_plus) != 1:
        raise DigsecError('Missing arguments, see usage')
    else:
        an_rrset_filename = non_plus[0]
        ensure_file_exists(an_rrset_filename)
    flags = parse_flags(argv[3:], {})
    dprint(flags)
    print_answer_file(an_rrset_filename)
