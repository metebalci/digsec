# coding: utf-8
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-name
"""
handles answers
"""
import os.path
from struct import pack, unpack
from digsec import dprint
from digsec.messages import DNSRR


def write_answer_file(filepath, rrlist):
    dprint('writing answer file: %s' % filepath)
    num_rrs = len(rrlist)
    dprint('num_rrs: %d' % num_rrs)
    with open(filepath, 'wb') as f:
        f.write(pack('! H', num_rrs))
        for rr in rrlist:
            rr_packet = rr.to_packet()
            len_rr = len(rr_packet)
            dprint('len_rr: %d' % len_rr)
            f.write(pack('! H', len_rr))
            f.write(rr.to_packet())
    dprint('write finished')


def save_section(output_dir, filename_prefix, section):
    rrs_per_type = {}
    for rr in section:
        if rr.type_str not in rrs_per_type:
            if rr.type_str == 'RRSIG':
                rrs_per_type[rr.type_str] = {}
            else:
                rrs_per_type[rr.type_str] = []
        if rr.type_str == 'RRSIG':
            type_covered = rr.l2().type_covered
            if type_covered not in rrs_per_type[rr.type_str]:
                rrs_per_type[rr.type_str][type_covered] = []
            rrs_per_type[rr.type_str][type_covered].append(rr)
        else:
            rrs_per_type[rr.type_str].append(rr)
    dprint('save_answer_file keys: %s' % rrs_per_type.keys())
    if 'RRSIG' in rrs_per_type:
        dprint('save_answer_file RRSIG keys: %s' %
               rrs_per_type['RRSIG'].keys())
    for k, v in rrs_per_type.items():
        if k == 'RRSIG':
            for k2, v2 in v.items():
                filename = '%s.%s.%s' % (filename_prefix, k, k2)
                dprint('output_dir: %s, filename: %s' %
                       (output_dir, filename))
                filepath = os.path.join(output_dir, filename)
                dprint('filepath: %s' % filepath)
                write_answer_file(filepath, v2)
        else:
            filename = '%s.%s' % (filename_prefix, k)
            dprint('output_dir: %s, filename: %s' % (output_dir, filename))
            filepath = os.path.join(output_dir, filename)
            dprint('filepath: %s' % filepath)
            write_answer_file(filepath, v)


def read_answer_file(filename):
    dprint('reading answer file: %s' % filename)
    rrs = []
    with open(filename, "rb") as f:
        num_rrs, = unpack('! H', f.read(2))
        dprint('num_rrs: %d' % num_rrs)
        for _i in range(0, num_rrs):
            len_rr, = unpack('! H', f.read(2))
            dprint('len_rr: %d' % len_rr)
            rr = f.read(len_rr)
            dnsrr, _offset = DNSRR.from_packet(rr, 0)
            dprint('answer: %s' % str(dnsrr))
            rrs.append(dnsrr)
    dprint('read finished')
    return rrs


def print_answer_file(filename):
    print('--- start of %s ---' % filename)
    rrs = read_answer_file(filename)
    for rr in rrs:
        print('%s' % str(rr.l2()))
    print('--- end ---')
