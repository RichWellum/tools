#!/usr/bin/env python

'''
hw_cmp.py - Scan through JSON files from Ironic introspection and pull
common information out, in order to classify the hardware

Purpose
=======

A tool to scan multiple JSON files and determine some basic information
that would lead the user to understand what type of OpenStack Node they are:
compute, controller, storage.

The data has been retrieved with:

openstack baremetal node list
openstack baremetal introspection data save server-1 | jq '.' > server-1.json

TODO: Import common_ironic and use API, instead of files pulled independently
'''

from __future__ import print_function
import argparse
from argparse import RawDescriptionHelpFormatter
# import json
import logging
from operator import itemgetter
# import os
import pprint
import re
import subprocess
import sys

logger = logging.getLogger(__name__)

pp = pprint.PrettyPrinter(indent=2)


def set_logging():
    '''Set basic logging format.'''

    FORMAT = "[%(asctime)s.%(msecs)03d %(levelname)8s: "\
        "%(funcName)20s:%(lineno)s] %(message)s"
    logging.basicConfig(format=FORMAT, datefmt="%H:%M:%S")


class AbortScriptException(Exception):
    '''Abort the script and clean up before exiting.'''


def parse_args():
    '''Parse sys.argv and return args'''

    parser = argparse.ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description='This tool sorts through supplied JSON files and searches '
        'for common paramters in order to identify potential H/W for compute, '
        'controller and storage.',
        epilog='E.g.: hw_cmp file1.json files2.json\n')

    # parser.add_argument('file', type=argparse.FileType('r'), nargs='+')
    parser.add_argument('-f', '--filter', type=str, default='manufacturer',
                        help='Sort filer, E.g: cpus, vendor, nic_num, '
                        'disk_num. Default is "manufacturer"')
    parser.add_argument('-v', '--verbose', action='store_const',
                        const=logging.DEBUG, default=logging.INFO,
                        help='Turn on verbose messages')
    parser.add_argument('-lk', '--list_keys', action='store_true',
                        help='Dump all valid keys, to find something to '
                        'filer "-f" on')
    return parser.parse_args()


def run_shell(args, cmd):
    '''Run a shell command and return the output

    Print the output and errors if debug is enabled
    Not using logger.debug as a bit noisy for this info
    '''

    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True)
    out, err = p.communicate()

    out = out.rstrip()
    err = err.rstrip()

    if args.verbose == 10:  # Hack - debug enabled
        if str(out) is not '0' and str(out) is not '1' and out:
            print("Shell STDOUT output: \n'%s'\n" % out)
        if err:
            print("Shell STDERR output: \n'%s'\n" % err)

    return(out)


def banner(description):
    '''Display a bannerized print'''

    banner = len(description)
    if banner > 100:
        banner = 100

    # First banner
    print('\n')
    for c in range(banner):
        print('*', end='')

    # Add description
    print('\n%s' % description)

    # Final banner
    for c in range(banner):
        print('*', end='')
    print('\n')


def print_global_list(args, list, dict_num):
    '''Print the whole global list for debug'''
    if args.verbose == 10:  # Hack - debug enabled
        banner('Global List of Dicts')
        for i in range(dict_num):
            pp.pprint(list[i])
            shared_items = set(list[0].items())
            for i in range(dict_num):
                shared_items = shared_items & set(list[i].items())
            print (len(shared_items))


def find(key, dictionary):
    '''Currently unused'''
    for k, v in dictionary.iteritems():
        if k == key:
            yield v
        elif isinstance(v, dict):
            for result in find(key, v):
                yield result
        elif isinstance(v, list):
            for d in v:
                for result in find(key, d):
                    yield result


def format_as_table(data,
                    keys,
                    header=None,
                    sort_by_key=None,
                    sort_order_reverse=False):
    """Takes a list of dictionaries, formats the data, and returns
    the formatted data as a text table.

    Required Parameters:
        data - Data to process (list of dictionaries). (Type: List)
        keys - List of keys in the dictionary. (Type: List)

    Optional Parameters:
        header - The table header. (Type: List)
        sort_by_key - The key to sort by. (Type: String)
        sort_order_reverse - Default sort order is ascending, if
            True sort order will change to descending. (Type: Boolean)
    """
    # Sort the data if a sort key is specified (default sort order
    # is ascending)
    if sort_by_key:
        data = sorted(data,
                      key=itemgetter(sort_by_key),
                      reverse=sort_order_reverse)

    # If header is not empty, add header to data
    if header:
        # Get the length of each header and create a divider based
        # on that length
        header_divider = []
        for name in header:
            header_divider.append('-' * len(name))

        # Create a list of dictionary from the keys and the header and
        # insert it at the beginning of the list. Do the same for the
        # divider and insert below the header.
        header_divider = dict(zip(keys, header_divider))
        data.insert(0, header_divider)
        header = dict(zip(keys, header))
        data.insert(0, header)

    column_widths = []
    for key in keys:
        column_widths.append(max(len(str(column[key])) for column in data))

    # Create a tuple pair of key and the associated column width for it
    key_width_pair = zip(keys, column_widths)

    format = ('%-*s ' * len(keys)).strip() + '\n'
    formatted_data = ''
    for element in data:
        data_to_format = []
        # Create a tuple that will be used for the formatting in
        # width, value format
        for pair in key_width_pair:
            data_to_format.append(pair[1])
            data_to_format.append(element[pair[0]])
        formatted_data += format % tuple(data_to_format)
    return formatted_data


def num_cpus(list):
    '''Format table of CPU's per file name

    Example of just looking at CPU's

    Currently not used'''
    logger.debug('CPU ANALYSIS')
    header = ['Name', 'CPU']
    keys = ['file_name', 'cpus']
    sort_by_key = 'cpus'
    sort_order_reverse = True

    print(format_as_table(list,
                          keys,
                          header,
                          sort_by_key,
                          sort_order_reverse))


def check_all_keys(list, key):
    '''Check entire list of dictionaries for a valid key'''
    all_keys = set().union(*(d.keys() for d in list))
    if not re.search(str(key), str(all_keys)):
        print('Error: %s is not a valid key, use "-k" to see valid keys')
        sys.exit(1)


def list_all_keys(args, list):
    '''List all valid keys'''
    if args.list_keys:
        all_keys = set().union(*(d.keys() for d in list))
        pp.pprint(all_keys)
        sys.exit(1)


def analyse_data(args, list):
    '''Gather information from global list to categorize the hardware

    High level Groups:

    manufacturer and vendor

    Number Nics

    Number of Disks
    '''

    # Only runs if -lk is added
    list_all_keys(args, list)

    # Check that passed key filter is valid
    check_all_keys(list, args.filter)

    header = ['Name', 'CPU', 'Disks Num', 'Memory Size',
              'NICS Num', 'Disk Size', 'Disk Vendor',
              'Product Name', 'Manufacturer']

    keys = ['file_name', 'cpus', 'disk_num', 'memory',
            'nic_num', 'size', 'vendor', 'product_name',
            'manufacturer']

    banner('Server "%s" HW Analysis' % args.filter)
    sort_order_reverse = True

    print(format_as_table(list,
                          keys,
                          header,
                          args.filter,
                          sort_order_reverse))


def check_key(key, list):
    '''Check if a key exists, return True or False'''

    if key in list:
        return True
    else:
        return False


def ihavealist():
    '''Dict of infor to manipulate'''

    list = []

    list = [
        {'bmc': u'192.168.117.177', 'cpu_arch': u'x86_64', 'numcpu': '48'},
        {'bmc': u'192.168.117.177',
         'product_name': u'ProLiant BL460c Gen9 (727021-B21)',
         'product_vendor': u'HP'},
        {'bmc': u'192.168.117.177',
         'disk_model': u'LOGICAL VOLUME',
         'disk_name': u'/dev/sda',
         'disk_vendor': u'HP',
         'numdisk': 2,
         'rotational': True,
         'size': 900151926784},
        {'bmc': u'192.168.117.177',
         'disk_model': u'LOGICAL VOLUME',
         'disk_name': u'/dev/sdb',
         'disk_vendor': u'HP',
         'numdisk': 2,
         'rotational': True,
         'size': 900151926784},
        {'bmc': u'192.168.117.177', 'name': u'eno49', 'numa_node': 0},
        {'bmc': u'192.168.117.177', 'name': u'eno50', 'numa_node': 0},
        {'bmc': u'192.168.117.177', 'name': u'ens1f1', 'numa_node': 0},
        {'bmc': u'192.168.117.177', 'name': u'ens1f0', 'numa_node': 0},
        {'biosdevname': u'em49',
         'bmc': u'192.168.117.177',
         'client_id': None,
         'has_carrier': True,
         'ipv4_address': u'172.31.4.3',
         'name': u'eno49',
         'numnic': '4',
         'product': u'0x10f8'},
        {'biosdevname': u'em50',
         'bmc': u'192.168.117.177',
         'client_id': None,
         'has_carrier': True,
         'ipv4_address': u'172.31.4.12',
         'name': u'eno50',
         'numnic': '4',
         'product': u'0x10f8'},
        {'biosdevname': u'p1p2',
         'bmc': u'192.168.117.177',
         'client_id': None,
         'has_carrier': True,
         'ipv4_address': u'172.31.4.11',
         'name': u'ens1f1',
         'numnic': '4',
         'product': u'0x10f8'},
        {'biosdevname': u'p1p1',
         'bmc': u'192.168.117.177',
         'client_id': None,
         'has_carrier': True,
         'ipv4_address': u'172.31.4.10',
         'name': u'ens1f0',
         'numnic': '4',
         'product': u'0x10f8'},
        {'bmc': u'192.168.117.184', 'cpu_arch': u'x86_64', 'numcpu': '100'},
        {'bmc': u'192.168.117.184',
         'product_name': u'ProLiant BL460c Gen33 (727021-B21)',
         'product_vendor': u'IBM'},
        {'bmc': u'192.168.117.184',
         'disk_model': u'LOGICAL VOLUME',
         'disk_name': u'/dev/sda',
         'disk_vendor': u'HP',
         'numdisk': 5,
         'rotational': True,
         'size': 900151926784},
        {'bmc': u'192.168.117.184',
         'disk_model': u'LOGICAL VOLUME',
         'disk_name': u'/dev/sdb',
         'disk_vendor': u'HP',
         'numdisk': 5,
         'rotational': True,
         'size': 900151926784},
        {'bmc': u'192.168.117.184', 'name': u'eno49', 'numa_node': 0},
        {'bmc': u'192.168.117.184', 'name': u'eno50', 'numa_node': 0},
        {'bmc': u'192.168.117.184', 'name': u'ens1f1', 'numa_node': 0},
        {'bmc': u'192.168.117.184', 'name': u'ens1f0', 'numa_node': 0},
        {'biosdevname': u'em49',
         'bmc': u'192.168.117.184',
         'client_id': None,
         'has_carrier': True,
         'ipv4_address': u'172.31.4.65',
         'name': u'eno49',
         'numnic': '8',
         'product': u'0x10f8'},
        {'biosdevname': u'em50',
         'bmc': u'192.168.117.184',
         'client_id': None,
         'has_carrier': True,
         'ipv4_address': u'172.31.4.12',
         'name': u'eno50',
         'numnic': '8',
         'product': u'0x10f8'},
        {'biosdevname': u'p1p2',
         'bmc': u'192.168.117.184',
         'client_id': None,
         'has_carrier': True,
         'ipv4_address': u'172.31.4.11',
         'name': u'ens1f1',
         'numnic': '8',
         'product': u'0x10f8'},
        {'biosdevname': u'p1p1',
         'bmc': u'192.168.117.184',
         'client_id': None,
         'has_carrier': True,
         'ipv4_address': u'172.31.4.10',
         'name': u'ens1f0',
         'numnic': '8',
         'product': u'0x10f8'},
        {'bmc': u'192.168.117.178', 'cpu_arch': u'x86_64', 'numcpu': '24'},
        {'bmc': u'192.168.117.178',
         'product_name': u'ProLiant BL460c Gen9 (727021-B21)',
         'product_vendor': u'HP'},
        {'bmc': u'192.168.117.178',
         'disk_model': u'LOGICAL VOLUME',
         'disk_name': u'/dev/sda',
         'disk_vendor': u'HP',
         'numdisk': 2,
         'rotational': True,
         'size': 900151926784},
        {'bmc': u'192.168.117.178',
         'disk_model': u'LOGICAL VOLUME',
         'disk_name': u'/dev/sdb',
         'disk_vendor': u'HP',
         'numdisk': 2,
         'rotational': True,
         'size': 900151926784},
        {'bmc': u'192.168.117.178', 'name': u'eno49', 'numa_node': 0},
        {'bmc': u'192.168.117.178', 'name': u'eno50', 'numa_node': 0},
        {'bmc': u'192.168.117.178', 'name': u'ens1f1', 'numa_node': 0},
        {'bmc': u'192.168.117.178', 'name': u'ens1f0', 'numa_node': 0},
        {'biosdevname': u'em49',
         'bmc': u'192.168.117.178',
         'client_id': None,
         'has_carrier': True,
         'ipv4_address': u'172.31.4.1',
         'name': u'eno49',
         'numnic': '10',
         'product': u'0x10f8'},
        {'biosdevname': u'em50',
         'bmc': u'192.168.117.178',
         'client_id': None,
         'has_carrier': True,
         'ipv4_address': u'172.31.4.4',
         'name': u'eno50',
         'numnic': '10',
         'product': u'0x10f8'},
        {'biosdevname': u'p1p2',
         'bmc': u'192.168.117.178',
         'client_id': None,
         'has_carrier': True,
         'ipv4_address': u'172.31.4.6',
         'name': u'ens1f1',
         'numnic': '10',
         'product': u'0x10f8'},
        {'biosdevname': u'p1p1',
         'bmc': u'192.168.117.178',
         'client_id': None,
         'has_carrier': True,
         'ipv4_address': u'172.31.4.5',
         'name': u'ens1f0',
         'numnic': '10',
         'product': u'0x10f8'},
        {'bmc': u'192.168.117.179', 'cpu_arch': u'x86_64', 'numcpu': '48'},
        {'bmc': u'192.168.117.179',
         'product_name': u'ProLiant BL460c Gen9 (727021-B21)',
         'product_vendor': u'HP'},
        {'bmc': u'192.168.117.179',
         'disk_model': u'LOGICAL VOLUME',
         'disk_name': u'/dev/sda',
         'disk_vendor': u'HP',
         'numdisk': 3,
         'rotational': True,
         'size': 900151926784},
        {'bmc': u'192.168.117.179',
         'disk_model': u'LOGICAL VOLUME',
         'disk_name': u'/dev/sdb',
         'disk_vendor': u'HP',
         'numdisk': 3,
         'rotational': True,
         'size': 900151926784},
        {'bmc': u'192.168.117.179', 'name': u'eno49', 'numa_node': 0},
        {'bmc': u'192.168.117.179', 'name': u'eno50', 'numa_node': 0},
        {'bmc': u'192.168.117.179', 'name': u'ens1f1', 'numa_node': 0},
        {'bmc': u'192.168.117.179', 'name': u'ens1f0', 'numa_node': 0},
        {'biosdevname': u'em49',
         'bmc': u'192.168.117.179',
         'client_id': None,
         'has_carrier': True,
         'ipv4_address': u'172.31.4.2',
         'name': u'eno49',
         'numnic': '4',
         'product': u'0x10f8'},
        {'biosdevname': u'em50',
         'bmc': u'192.168.117.179',
         'client_id': None,
         'has_carrier': True,
         'ipv4_address': u'172.31.4.9',
         'name': u'eno50',
         'numnic': '4',
         'product': u'0x10f8'},
        {'biosdevname': u'p1p2',
         'bmc': u'192.168.117.179',
         'client_id': None,
         'has_carrier': True,
         'ipv4_address': u'172.31.4.8',
         'name': u'ens1f1',
         'numnic': '4',
         'product': u'0x10f8'},
        {'biosdevname': u'p1p1',
         'bmc': u'192.168.117.179',
         'client_id': None,
         'has_carrier': True,
         'ipv4_address': u'172.31.4.7',
         'name': u'ens1f0',
         'numnic': '4',
         'product': u'0x10f8'}
    ]
    return(list)


def only_group_data(list):
    '''Return only data relevant to the groups'''

    only_group_data = []
    for dict in list:   # For each dict
        for key, value in dict.iteritems():
            if key == 'product_name' or key == 'numdisk' or key == 'numnic':
                only_group_data.append(dict)
    return(only_group_data)


def uniquify_list_dict(list):
    '''Take a list of dicts and remove all but unique dicts'''

    seen = set()
    unique_list = []

    # pp.pprint(list)
    list.sort()

    for d in list:
        t = tuple(d.items())
        if t not in seen:
            seen.add(t)
            unique_list.append(d)
            logger.debug('Unique list: \n {}'
                         .format(unique_list))
    return(unique_list)


def unique(list1):
    '''Python program to get unique values from list
    using traversal'''

    # intialize a null list
    unique_list = []
    unique_set = []

    # traverse for all elements
    for x in list1:
        # check if exists in unique_list or not
        if x not in unique_list:
            unique_list.append(x)
    # print list
    for x in unique_list:
        unique_set.append(x)
        # print(x,)
    return(unique_set)


def create_groups(list):
    '''create groups'''

    group_keys = []

    pr_name = {}
    for dict in list:
        for key, value in dict.iteritems():
            if key == 'product_name':
                key_ = '%s_%s' % (key, value)
                if key_ in pr_name.keys():
                    pr_name[key_].append(dict['bmc'])
                else:
                    pr_name[key_] = [dict['bmc']]
    group_keys.append(pr_name)

    pr_vendor = {}
    for dict in list:
        for key, value in dict.iteritems():
            if key == 'product_vendor':
                key_ = '%s_%s' % (key, value)
                if key_ in pr_vendor.keys():
                    pr_vendor[key_].append(dict['bmc'])
                else:
                    pr_vendor[key_] = [dict['bmc']]
    group_keys.append(pr_vendor)

    numnic = {}
    for dict in list:
        for key, value in dict.iteritems():
            if key == 'numnic':
                key_ = '%s_%s' % (key, value)
                if key_ in numnic.keys():
                    if dict['bmc'] not in numnic[key_]:
                        numnic[key_].append(dict['bmc'])
                else:
                    numnic[key_] = [dict['bmc']]
    group_keys.append(numnic)

    numdisk = {}
    for dict in list:
        for key, value in dict.iteritems():
            if key == 'numdisk':
                key_ = '%s_%s' % (key, value)
                if key_ in numdisk.keys():
                    if dict['bmc'] not in numdisk[key_]:
                        numdisk[key_].append(dict['bmc'])
                else:
                    numdisk[key_] = [dict['bmc']]
    group_keys.append(numdisk)

    pp.pprint(group_keys)


def main():
    '''Main function.'''

    args = parse_args()

    set_logging()
    logger.setLevel(level=args.verbose)

    # Store a list of dictionaries - each dict representing one inputed file
    global_list = ihavealist()

    try:
        print('RAW DATA:')
        # pp.pprint(global_list)

        print('UNIQUE DATA:')
        unique_data = uniquify_list_dict(global_list)
        # pp.pprint(unique_data)

        ogd = only_group_data(unique_data)
        print('ONLY GROUP DATA')
        # pp.pprint(ogd)

        create_groups(ogd)

    except Exception:
        print('Exception caught:')
        print(sys.exc_info())
        raise


if __name__ == '__main__':
    main()
