import grp
import pwd
from contextvars import ContextVar
from typing import Callable, Tuple, Type


class UserError(Exception):
    def __init__(self, msg):
        super().__init__(self, msg)

class OSFunctions:
    getpwuid = pwd.getpwuid
    getpwnam = pwd.getpwnam
    getgrnam = grp.getgrnam

osfuns: ContextVar[Type[OSFunctions]] = ContextVar('osfuns', default=OSFunctions)

def parse_chown_usergroup(usergroup: str) -> Tuple[int, int]:
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

    uname2uid = lambda name: osfuns.get().getpwnam(name).pw_uid
    gname2gid = lambda name: osfuns.get().getgrnam(name).gr_gid

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
                gid = osfuns.get().getpwuid(uid).pw_gid
            except KeyError:
                gid = uid
        except ValueError:
            try:
                pwd_entry = osfuns.get().getpwnam(user_spec)
                uid = pwd_entry.pw_uid
                gid = pwd_entry.pw_gid
            except KeyError:
                raise UserError('Unknown user/group ' + user_spec)

    return (uid, gid)
