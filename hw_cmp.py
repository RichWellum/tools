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
import json
import logging
from operator import itemgetter
import os
import pprint
import re
import subprocess
import sys

logger = logging.getLogger(__name__)

pp = pprint.PrettyPrinter(indent=4)


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

    parser.add_argument('file', type=argparse.FileType('r'), nargs='+')
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


def grab_data(args):
    '''Grab data from a server

    openstack baremetal node list
    openstack baremetal introspection data save server-1 \
     | jq '.' > server-1.json

    Results in a file of data for every Ironic Server found.

    Return dict of files
    '''
    # cmd = "for fn in `openstack baremetal node list | awk -F \
    # '|' '{print $3}' | grep -v Name`; do openstack baremetal \
    # introspection data save \"$fn\" | jq '.' > '/tmp/$fn.json'; done"

    cmd = "for fn in `openstack baremetal node list | awk -F '|' \
    '{print $3}' | grep -v Name`; do openstack baremetal \
    introspection data save \"$fn\" | jq '.' > \"/tmp/$fn.json\"; done"

    cmd = "for fn in `openstack baremetal node list | awk -F '|' \
    '{print $3}' | grep -v Name`; do echo $fn; done"

    servers = []
    servers = run_shell(args, cmd)
    pp.pprint(servers)

    results = []
    folder = '/tmp'

    for f in os.listdir(folder):
        if f.endswith('.json'):
            results.append(f)

    print(results)


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


def main():
    '''Main function.'''

    args = parse_args()

    set_logging()
    logger.setLevel(level=args.verbose)

    # Calculate number of lists
    total_list_num = 0
    for file in args.file:
        total_list_num += 1

    grab_data(args)
    sys.exit(1)

    # Store a list of dictionaries - each dict representing one inputed file
    global_list = []

    try:
        for file in args.file:
            d = {}
            logger.debug('FILE: %s' % file.name)
            d['file_name'] = '%s' % file.name
            json_str = file.read()
            data = json.loads(json_str)

            # Based on your input string, data is now a
            # dictionary that contains other dictionaries.
            # You can just navigate up the dictionaries like so:

            logger.debug('High Level')
            # cpu_arch
            node = data['cpu_arch']
            logger.debug('  %s: %s' % ('cpu_arch', str(node)))
            d['cpu_arch'] = str(node)

            # cpu
            node = data['cpus']
            logger.debug('  %s: %s' % ('cpus', str(node)))
            d['cpus'] = str(node)

            logger.debug('root disk')
            # root_disk : vendor
            node = data['root_disk']['vendor']
            logger.debug('  %s: %s' % ('vendor', str(node)))
            d['vendor'] = str(node)

            # root_disk : name
            node = data['root_disk']['name']
            logger.debug('  %s: %s' % ('name', str(node)))
            d['name'] = str(node)

            # root_disk : size
            node = data['root_disk']['size']
            logger.debug('  %s: %s' % ('size', str(node)))
            d['size'] = str(node)

            # Inventory Disks - total
            i = 0
            for x in data['inventory']['disks']:
                node = x['vendor']
                logger.debug('  %s:%s: %s' % (i, 'disk vendor', str(node)))
                i += 1
            d['disk_num'] = i

            # Inventory memory
            node = data['inventory']['memory']['total']
            logger.debug('  %s: %s' % ('memory', str(node)))
            d['memory'] = str(node)

            # Numa
            i = 0
            if check_key('numa_topology', data):
                for x in data['numa_topology']['nics']:
                    node1 = x['numa_node']
                    logger.debug('  %s:%s: %s' % (i, 'numa_node', str(node1)))
                    nn = '%s-numa-' % i + str(node1)
                    node2 = x['name']
                    nnc = str(node2) + '-%s' % i
                    logger.debug('  %s:%s: %s' % (i, 'name', str(node2)))
                    d[nn] = nnc
                    i += 1

            # Inventory: Interfaces name
            logger.debug('Inventory')
            node = data['inventory']['bmc_address']
            logger.debug('  %s: %s' % ('bmc_address', str(node)))
            d['bmc_address'] = str(node)

            i = 0
            for x in data['inventory']['interfaces']:
                node = x['name']
                logger.debug('  %s: %s' % ('nic_name', str(node)))
                d['%s-nic_name' % i] = str(node)

                node = x['product']
                logger.debug('    %s: %s' % ('product', str(node)))
                d['%s-product' % i] = str(node)

                node = x['vendor']
                logger.debug('    %s: %s' % ('vendor', str(node)))
                d['%s-vendor' % i] = str(node)

                node = x['has_carrier']
                logger.debug('    %s: %s' % ('has_carrier', str(node)))
                d['%s-has_carrier' % i] = str(node)

                node = x['ipv4_address']
                logger.debug('    %s: %s' % ('ipv4_address', str(node)))
                d['%s-ipv4_address' % i] = str(node)

                if check_key('biosdevname', x):
                    node = x['biosdevname']
                    logger.debug('    %s: %s' % ('biosdevname', str(node)))
                    d['%s-biosdevname' % i] = str(node)

                if check_key('client_id', x):
                    node = x['client_id']
                    logger.debug('    %s: %s' % ('client_id', str(node)))
                    d['%s-client_id' % i] = str(node)

                i += 1

            d['nic_num'] = i

            # Inventory: Interfaces System Vendor
            node = data['inventory']['system_vendor']['product_name']
            logger.debug('  %s: %s' % ('product_name', str(node)))
            d['product_name'] = str(node)

            node = data['inventory']['system_vendor']['manufacturer']
            logger.debug('  %s: %s' % ('manufacturer', str(node)))
            d['manufacturer'] = str(node)

            global_list.append(d)

        # This only prints if verbose is on
        print_global_list(args, global_list, total_list_num)

        analyse_data(args, global_list)

    except Exception:
        print('Exception caught:')
        print(sys.exc_info())
        raise


if __name__ == '__main__':
    main()
