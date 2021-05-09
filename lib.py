import pwd, grp
import sys, os, stat
from dataclasses import dataclass, replace
from typing import Callable, Optional, Set, Tuple

def show_usage(usage, exit_code=0, msg=None):
    out = sys.stderr if exit_code else sys.stdout
    if msg:
        print(str(msg), file=out)
    print(usage, file=out)
    sys.exit(exit_code)

class UserError(Exception):
    def __init__(self, msg):
        super().__init__(self, msg)

class OSFunctions:
    getpwuid = pwd.getpwuid
    getpwnam = pwd.getpwnam
    getgrnam = grp.getgrnam
    stat = os.stat
    scandir = os.scandir

def parse_chown_usergroup(usergroup: str, osfns=OSFunctions) -> Tuple[int, int]:
    """ """

    sep_idx = usergroup.find(':')
    if sep_idx == -1:
        # undocumented but supported by both coreutils and busybox
        sep_idx = usergroup.find('.')

    def get_ug_id(name: str, name2id: Callable[[str], int]) -> int:
        try:
            return int(name)
        except ValueError:
            try:
                return name2id(name)
            except KeyError:
                raise UserError(f"unknown user/group '{name}'")

    uname2uid = lambda name: osfns.getpwnam(name).pw_uid
    gname2gid = lambda name: osfns.getgrnam(name).gr_gid

    if sep_idx == -1:
        # 'user'
        uid = get_ug_id(usergroup, uname2uid)
        gid = -1
    elif sep_idx == 0:
        # ':group'
        uid = -1
        gid = get_ug_id(usergroup[1:], gname2gid)
    elif sep_idx != len(usergroup) - 1:
        # 'user:group'
        uid = get_ug_id(usergroup[:sep_idx], uname2uid)
        gid = get_ug_id(usergroup[(sep_idx + 1):], gname2gid)
    else:
        # 'user:' - use user's primary group
        user_spec = usergroup[:sep_idx]
        try:
            # 'uid:' works in busybox, not in coreutils
            uid = int(user_spec)
            try:
                gid = osfns.getpwuid(uid).pw_gid
            except KeyError:
                gid = uid
        except ValueError:
            try:
                pwd_entry = osfns.getpwnam(user_spec)
                uid = pwd_entry.pw_uid
                gid = pwd_entry.pw_gid
            except KeyError:
                raise UserError(f"unknown user/group 'user_spec'")

    return (uid, gid)

@dataclass
class RecurseOpts:
    recurse: bool = False
    depth_first: bool = False
    follow_top_symlink: bool = False
    follow_child_symlinks: bool = False
    sort_dirs: bool = True

def recurse_action(
        file: str,
        action: Callable[[str, os.stat_result, Optional[object]], bool],
        recurse_opts: RecurseOpts,
        user_data: Optional[object] = None,
        depth=0,  # unused for now
        visited: Optional[Set[Tuple[int, int]]] = None,
        osfns=OSFunctions):
    """ """

    if visited is None:
        visited = set()

    file_stat = osfns.stat(file, follow_symlinks=recurse_opts.follow_top_symlink)

    file_dev_ino = (file_stat.st_dev, file_stat.st_ino)
    if file_dev_ino in visited:
        return
    visited.add(file_dev_ino)

    if not (recurse_opts.recurse and stat.S_ISDIR(file_stat.st_mode)):
        return action(file, file_stat, user_data)

    if recurse_opts.depth_first:
        if action(file, file_stat, user_data):
            return

    dir_iter = osfns.scandir(file)
    if recurse_opts.sort_dirs:
        dir_iter = sorted(dir_iter, key=lambda e: e.name)

    for child in dir_iter:
        recurse_action(
            str(child.path),
            action,
            replace(recurse_opts, follow_top_symlink=recurse_opts.follow_child_symlinks),
            user_data=user_data,
            depth=(depth + 1),
            visited=visited,
            osfns=OSFunctions)

    if not recurse_opts.depth_first:
        action(file, file_stat, user_data)
