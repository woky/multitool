#!/usr/bin/env python3

import getopt
import sys
import os
from typing import List

from . import lib

def chown_usage(chgrp: bool, exit_code=0, msg=None):
    if chgrp:
        usage = f'Usage: {sys.argv[0]} chgrp [option]... group <file>...'
    else:
        usage = f'Usage: {sys.argv[0]} chown [option]... [owner][:[group]] <file>...'
    lib.show_usage(usage, exit_code, msg)

def do_chown(args: List[str], chgrp=False):
    opts, args = getopt.gnu_getopt(args, 'hRHLP', ['help'])
    if len(args) < 2:
        chown_usage(chgrp, 1)
    usergroup, files = args[0], args[1:]
    if chgrp:
        usergroup = ':' + usergroup
    recurse_opts = lib.RecurseOpts()
    chown_fn = os.chown
    for opt, optarg in opts:
        if opt == '-h':
            if not args:
                chown_usage(chgrp)
            chown_fn = os.lchown
        elif opt == '--help':
            chown_usage(chgrp)
        elif opt == '-R':
            recurse_opts.recurse = True
        elif opt == '-H':
            recurse_opts.follow_top_symlink = True
            recurse_opts.follow_child_symlinks = False
        elif opt == '-L':
            recurse_opts.follow_top_symlink = True
            recurse_opts.follow_child_symlinks = True
        elif opt == '-P':
            recurse_opts.follow_top_symlink = False
            recurse_opts.follow_child_symlinks = False
    if recurse_opts.recurse and not recurse_opts.follow_top_symlink:
        chown_fn = os.lchown
    try:
        uid, gid = lib.parse_chown_usergroup(usergroup)
    except lib.UserError as e:
        sys.exit(e.args[1])
    def action(filename, st: os.stat_result, data):
        if (uid != -1 and st.st_uid != uid) or (gid != -1 and st.st_gid != gid):
            chown_fn(filename, uid, gid)
            print(filename)
    try:
        for f in files:
            lib.recurse_action(f, action, recurse_opts)
    except OSError as e:
        sys.exit(e)

def do_chgrp(args: List[str]):
    do_chown(args, chgrp=True)

def do_chmod(args: List[str]):
    pass

subcommands = {
    'chown': do_chown,
    'chgrp': do_chgrp,
    'chmod': do_chmod,
}

def main_usage(exit_code=0, msg=None):
    subcmds = '|'.join(subcommands.keys())
    usage = f'Usage: {sys.argv[0]} {subcmds} <args>...'
    lib.show_usage(usage, exit_code, msg)

def main(args: List[str] = None) -> None:
    if args is None:
        args = sys.argv[1:]
    try:
        opts, args = getopt.getopt(args, 'h', ['help'])
    except getopt.GetoptError as e:
        main_usage(1, e)
    for opt, optarg in opts:
        if opt == '-h' or opt == '--help':
            main_usage()
    if not args:
        main_usage(1)
    subcmd_fn = subcommands.get(args[0])
    if not subcmd_fn:
        main_usage(1, f"unrecognized command '{args[0]}'")
    subcmd_fn(args[1:])

if __name__ == '__main__':
    main()
