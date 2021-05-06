import grp
import os
import pwd
import stat
from typing import Callable, Set, Tuple, Type, Union


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
                raise UserError('Unknown user/group ' + name)

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
                raise UserError('Unknown user/group ' + user_spec)

    return (uid, gid)

def recurse_action(
        file: str,
        action: Callable[[str, os.stat_result], bool],
        recurse=False,
        pre_order=False,
        follow_top_symlink=False,
        follow_child_symlinks=False,
        sort_dirs=False,
        depth=0,  # unused for now
        visited: Set[Tuple[int, int]] = None,
        osfns=OSFunctions):
    """ """

    if visited is None:
        visited = set()

    file_stat = osfns.stat(file, follow_symlinks=follow_top_symlink)

    file_dev_ino = (file_stat.st_dev, file_stat.st_ino)
    if file_dev_ino in visited:
        return
    visited.add(file_dev_ino)

    if not (stat.S_ISDIR(file_stat.st_mode) and recurse):
        return action(file, file_stat)

    if pre_order:
        if action(file, file_stat):
            return

    dir_iter = osfns.scandir(file)
    if sort_dirs:
        dir_iter = sorted(dir_iter, key=lambda e: e.name)

    for child in dir_iter:
        recurse_action(
            str(child.path),
            action,
            recurse=True,
            pre_order=pre_order,
            follow_top_symlink=follow_child_symlinks,
            follow_child_symlinks=follow_child_symlinks,
            sort_dirs=sort_dirs,
            depth=(depth + 1),
            visited=visited,
            osfns=OSFunctions)

    if not pre_order:
        action(file, file_stat)
