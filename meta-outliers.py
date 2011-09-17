#!/usr/bin/env python
# 
# Author: Dave Hull
# License: We don't need no stinking license. I hereby place
# this in the public domain.
#
# Todo: 
# 
# Much more, this is just a PoC/starting point.

import re, os, math, argparse

parser = argparse.ArgumentParser(description = \
    'meta-outliers.py finds files with metadata addresses outside n standard ' \
    'deviations of the average metadata address on a per directory basis. ' \
    'Default value for n is 1. meta-outliers.py is meant to be run against ' \
    'the output of Brian Carrier\'s fls (see The Sleuth Kit), specifically ' \
    'the output of fls -arp. The theory is that an attacker\'s code on a file ' \
    'system may have metadata addresses outside the normal range of values ' \
    'for a given directory where the malicious files were installed.')
parser.add_argument('--devs', help = '--devs defines the outlier threshold. ' \
    'Default is 1, higher values will further reduce the data set.', \
    dest = 'stddevs', default = 1.0)
parser.add_argument('--file', help = 'Output from Brian Carrier\'s fls -arp ' \
    '(The Sleuth Kit) that has been saved to a file for processing.', \
    dest = 'filename')
args = parser.parse_args()

def get_deviants():
    current_path    = None
    meta_addr_total = 0
    deviation       = {}
    dev_sum         = 0
    stddevs         = float(args.stddevs)   # Modify this to control what files are included in results. Default, anything above 1 std dev
    path            = {}

    print "Metadata address outliers that are %2.2f standard deviations from their path average." % (stddevs)
    print "====================================================================================="

    fi = open(args.filename, 'rb')
    if fi.read(1) == '0':
        fi.seek(0)
        for line in fi:
            md5,ppath,inode,mode,uid,gid,size,atime,mtime,ctime,crtime = line.split("|")
            meta = inode.split("-")
            meta_addr = int(meta[0])

            if meta_addr == 0:
                continue

            fname = os.path.basename(ppath).rstrip()
            if fname == ".." or fname == ".":
                continue

            pname = os.path.dirname(ppath).rstrip()
            if pname not in path:
                path[pname] = {}

            path[pname][fname] = meta_addr
                
    else:
        fls = "./.\s(?P<deleted>\**\s*)(?P<meta_addr>\d+)-?" \
              "(?P<meta_type>\d{3})?-?(?P<meta_id>\d+)?:\s(?P<path>.*$)"
        pattern = re.compile(fls)
        fi.seek(0)

        for line in fi:
            matches = pattern.finditer(line)
            for m in matches:
                if m.group('deleted'):         # Skip deleted files
                    continue

                meta_addr = int(m.group('meta_addr'))
                if meta_addr == 0:
                    continue

                fname = os.path.basename(m.group('path')).rstrip()

                if fname == ".." or fname == ".":       # Parent directories skew path averages
                    continue                            # On some systems '.' is different enough to skew

                pname = os.path.dirname(m.group('path')).rstrip()
                if len(pname) == 0:
                    pname = "/"

                if pname not in path:
                    path[pname] = {}

                path[pname][fname] = meta_addr

    items = [(pname, fname) for pname, fname in path.items()]
    items.sort()

    for pname, fname in items:
        files = [(filename, meta_addr) for filename, meta_addr in fname.items()]
        files.sort()
        file_cnt = len(files)
        if file_cnt > 1:
            for filename, meta_addr in files:
                meta_addr_total += meta_addr

            avg = meta_addr_total / file_cnt

            for filename, meta_addr in files:
                deviation[filename] = meta_addr - avg
                dev_sum += (deviation[filename] ** 2)

            std_dev = math.sqrt((dev_sum * 1.0) / (file_cnt * 1.0))

            no_header = True
            for filename, meta_addr in files:
                if math.fabs(deviation[filename]) > (stddevs * std_dev):
                    if no_header:
                        print "\nPath Meta Addr Avg: %10d -- Std. Dev.: %12.2f -- Path: %s" % (avg, std_dev, pname)
                        no_header = False
                    print "    File Meta Addr: %10d --      Dev.: %12.2f -- File:   %s" % (meta_addr, deviation[filename], filename)

            meta_addr_total = dev_sum = 0

get_deviants()
