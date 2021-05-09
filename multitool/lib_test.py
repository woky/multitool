import os.path
import types
from dataclasses import dataclass
from pathlib import Path
import stat
from typing import Tuple

import pytest

from . import lib


def test_parse_chown_usergroup():
    uid_by_name = {'alice': 1, 'bob': 2, 'cyril': 3}
    gid_by_name = {'alice': 1, 'bob': 3, 'adm': 4}
    prim_gid_by_uid = {1: 1, 2: 3, 3: 4}

    def test_getpwuid(uid: int):
        return types.SimpleNamespace(pw_uid=uid, pw_gid=prim_gid_by_uid[uid])
    def test_getpwnam(name: str):
        return test_getpwuid(uid_by_name[name])
    def test_getgrnam(name: str):
        return types.SimpleNamespace(gr_gid=gid_by_name[name])

    class TestOSFunctions(lib.OSFunctions):
        getpwuid = test_getpwuid
        getpwnam = test_getpwnam
        getgrnam = test_getgrnam

    def parse_wrapper(usergroup: str) -> Tuple[int, int]:
        _call = lambda ug: lib.parse_chown_usergroup(ug, osfns=TestOSFunctions)
        # try both colon and dot
        usergroup_dot = usergroup.replace(':', '.', 1)
        if usergroup == usergroup_dot:
            return _call(usergroup)
        try:
            r1 = _call(usergroup)
            try:
                r2 = _call(usergroup_dot)
            except lib.UserError:
                assert False
            assert r1 == r2
            return r1
        except lib.UserError as e:
            with pytest.raises(lib.UserError):
                _call(usergroup_dot)
            raise e

    # known user name
    assert parse_wrapper('alice') == (1, -1)
    assert parse_wrapper('bob') == (2, -1)
    assert parse_wrapper('cyril') == (3, -1)

    # known uid
    assert parse_wrapper('1') == (1, -1)
    assert parse_wrapper('2') == (2, -1)
    assert parse_wrapper('3') == (3, -1)

    # unknown/empty user name
    with pytest.raises(lib.UserError):
        parse_wrapper('nonexistent')
        parse_wrapper('foo')
        parse_wrapper('')

    # unknown uid
    assert parse_wrapper('5') == (5, -1)
    assert parse_wrapper('65534') == (65534, -1)

    # known group name
    assert parse_wrapper(':alice') == (-1, 1)
    assert parse_wrapper(':bob') == (-1, 3)
    assert parse_wrapper(':adm') == (-1, 4)

    # known gid
    assert parse_wrapper(':1') == (-1, 1)
    assert parse_wrapper(':3') == (-1, 3)
    assert parse_wrapper(':4') == (-1, 4)

    # unknown/empty group name
    with pytest.raises(lib.UserError):
        parse_wrapper(':nonexistent')
        parse_wrapper(':foo')
        parse_wrapper(':')

    # unknown gid
    assert parse_wrapper(':5') == (-1, 5)
    assert parse_wrapper(':65534') == (-1, 65534)

    # known 'user:group' names
    assert parse_wrapper('alice:alice') == (1, 1)
    assert parse_wrapper('bob:bob') == (2, 3)
    assert parse_wrapper('cyril:adm') == (3, 4)
    assert parse_wrapper('alice:bob') == (1, 3)
    assert parse_wrapper('cyril:alice') == (3, 1)
    assert parse_wrapper('bob:adm') == (2, 4)

    # unknown 'user:group' names
    with pytest.raises(lib.UserError):
        assert parse_wrapper('cyril:cyril')
        assert parse_wrapper('adm:nonexistent')
        assert parse_wrapper('nonexistent:adm')
        assert parse_wrapper('nonexistent:nonexistent')
        assert parse_wrapper('foo:bar')

    # 'user:group', known name, any ids
    assert parse_wrapper('alice:1') == (1, 1)
    assert parse_wrapper('alice:2') == (1, 2)
    assert parse_wrapper('alice:3') == (1, 3)
    assert parse_wrapper('alice:4') == (1, 4)
    assert parse_wrapper('alice:5') == (1, 5)
    assert parse_wrapper('alice:65534') == (1, 65534)
    assert parse_wrapper('bob:4') == (2, 4)
    assert parse_wrapper('cyril:3') == (3, 3)
    assert parse_wrapper('2:1') == (2, 1)
    assert parse_wrapper('2:2') == (2, 2)
    assert parse_wrapper('2:3') == (2, 3)
    assert parse_wrapper('2:4') == (2, 4)
    assert parse_wrapper('2:5') == (2, 5)
    assert parse_wrapper('2:65534') == (2, 65534)
    assert parse_wrapper('5:1') == (5, 1)
    assert parse_wrapper('5:2') == (5, 2)
    assert parse_wrapper('5:3') == (5, 3)
    assert parse_wrapper('5:4') == (5, 4)
    assert parse_wrapper('5:5') == (5, 5)
    assert parse_wrapper('5:65534') == (5, 65534)
    assert parse_wrapper('1:alice') == (1, 1)
    assert parse_wrapper('1:bob') == (1, 3)
    assert parse_wrapper('1:adm') == (1, 4)
    assert parse_wrapper('5:alice') == (5, 1)
    assert parse_wrapper('5:bob') == (5, 3)
    assert parse_wrapper('5:adm') == (5, 4)
    assert parse_wrapper('65534:alice') == (65534, 1)
    assert parse_wrapper('65534:bob') == (65534, 3)
    assert parse_wrapper('65534:adm') == (65534, 4)
    assert parse_wrapper('65534:65534') == (65534, 65534)

    # 'user:group', unknown name, any id
    with pytest.raises(lib.UserError):
        parse_wrapper('nonexistent:1')
        parse_wrapper('nonexistent:2')
        parse_wrapper('nonexistent:3')
        parse_wrapper('nonexistent:4')
        parse_wrapper('nonexistent:5')
        parse_wrapper('nonexistent:65534')
        parse_wrapper('1:nonexistent')
        parse_wrapper('2:nonexistent')
        parse_wrapper('3:nonexistent')
        parse_wrapper('4:nonexistent')
        parse_wrapper('5:nonexistent')
        parse_wrapper('65534:nonexistent')
        parse_wrapper('nonexistent:nonexistent')
        parse_wrapper('foo:bar')

    # 'user:', known name
    assert parse_wrapper('alice:') == (1, 1)
    assert parse_wrapper('bob:') == (2, 3)
    assert parse_wrapper('cyril:') == (3, 4)

    # 'user:', unknown name
    with pytest.raises(lib.UserError):
        parse_wrapper('nonexistent:')
        parse_wrapper('foo:')

    # 'user:', known uid
    assert parse_wrapper('1:') == (1, 1)
    assert parse_wrapper('2:') == (2, 3)
    assert parse_wrapper('3:') == (3, 4)

    # 'user:', unknown uid
    assert parse_wrapper('4:') == (4, 4)
    assert parse_wrapper('5:') == (5, 5)
    assert parse_wrapper('65534:') == (65534, 65534)


@dataclass
class TmpRoot:
    root: Path
    def mk_f(self, p):      (self.root / p).touch()
    def mk_d(self, p):      (self.root / p).mkdir()
    def mk_s(self, p, t):   (self.root / p).symlink_to(t)

def recurse_wrapper(root, start, realpath=False, **kwargs):
    walk_list = []
    def action(p, st: os.stat_result, user_data):
        if realpath and not stat.S_ISLNK(st.st_mode):
            p = os.path.realpath(p)
        rel_path = p[len(str(root))+1:]
        walk_list.append(rel_path)
    opts = lib.RecurseOpts(sort_dirs=True, **kwargs)
    lib.recurse_action(os.path.join(root, start), action, opts)
    return walk_list

def test_recurse_action_basic(tmp_path: Path):
    root = TmpRoot(tmp_path)
    root.mk_d('files')
    root.mk_d('files/A')
    root.mk_f('files/A/x')
    root.mk_f('files/A/y')
    root.mk_d('files/A/A')
    root.mk_f('files/A/A/x')
    root.mk_f('files/A/A/y')
    root.mk_d('files/A/B')
    root.mk_d('files/A/C')
    root.mk_f('files/A/C/x')

    assert recurse_wrapper(tmp_path, 'files/A') == ['files/A']
    assert recurse_wrapper(tmp_path, 'files/A/x') == ['files/A/x']
    assert recurse_wrapper(tmp_path, 'files', recurse=True) == [
        'files/A/A/x',
        'files/A/A/y',
        'files/A/A',
        'files/A/B',
        'files/A/C/x',
        'files/A/C',
        'files/A/x',
        'files/A/y',
        'files/A',
        'files',
    ]
    assert recurse_wrapper(tmp_path, 'files', recurse=True, depth_first=True) == [
        'files',
        'files/A',
        'files/A/A',
        'files/A/A/x',
        'files/A/A/y',
        'files/A/B',
        'files/A/C',
        'files/A/C/x',
        'files/A/x',
        'files/A/y',
    ]

def test_recurse_action_symlinks(tmp_path: Path):
    root = TmpRoot(tmp_path)
    root.mk_d('files')
    root.mk_d('files/A')
    root.mk_f('files/A/x')
    root.mk_f('files/A/y')
    root.mk_s('files/A/B', '../B/B')
    root.mk_d('files/B')
    root.mk_f('files/B/x')
    root.mk_f('files/B/y')
    root.mk_s('files/B/ax', '../A/x')
    root.mk_s('files/B/A', '../A')
    root.mk_d('files/B/B')
    root.mk_f('files/B/B/x')
    root.mk_f('files/B/B/y')
    root.mk_s('files/B/B/A', '../../A')

    no_follow_pre = [
        'files/A/B',
        'files/A/x',
        'files/A/y',
        'files/A',
        'files/B/A',
        'files/B/B/A',
        'files/B/B/x',
        'files/B/B/y',
        'files/B/B',
        'files/B/ax',
        'files/B/x',
        'files/B/y',
        'files/B',
        'files',
    ]
    assert recurse_wrapper(tmp_path, 'files',
            realpath=False, recurse=True) == no_follow_pre
    assert recurse_wrapper(tmp_path, 'files',
            realpath=True, recurse=True) == no_follow_pre

    no_follow_post = [
        'files',
        'files/A',
        'files/A/B',
        'files/A/x',
        'files/A/y',
        'files/B',
        'files/B/A',
        'files/B/B',
        'files/B/B/A',
        'files/B/B/x',
        'files/B/B/y',
        'files/B/ax',
        'files/B/x',
        'files/B/y',
    ]
    assert recurse_wrapper(tmp_path, 'files',
            realpath=False, recurse=True, depth_first=True) == no_follow_post
    assert recurse_wrapper(tmp_path, 'files',
            realpath=True, recurse=True, depth_first=True) == no_follow_post

    assert recurse_wrapper(tmp_path, 'files/A',
            realpath=False, recurse=True,
            follow_top_symlink=True, follow_child_symlinks=True,
    ) == [
        'files/A/B/x',
        'files/A/B/y',
        'files/A/B',
        'files/A/x',
        'files/A/y',
        'files/A',
    ]
    assert recurse_wrapper(tmp_path, 'files/A',
            realpath=True, recurse=True,
            follow_top_symlink=True, follow_child_symlinks=True,
    ) == [
        'files/B/B/x',
        'files/B/B/y',
        'files/B/B',
        'files/A/x',
        'files/A/y',
        'files/A',
    ]
    assert recurse_wrapper(tmp_path, 'files/B',
            realpath=False, recurse=True,
            follow_top_symlink=True, follow_child_symlinks=True,
    ) == [
        'files/B/A/B/x',
        'files/B/A/B/y',
        'files/B/A/B',
        'files/B/A/x',
        'files/B/A/y',
        'files/B/A',
        'files/B/x',
        'files/B/y',
        'files/B',
    ]
    assert recurse_wrapper(tmp_path, 'files/B',
            realpath=True, recurse=True,
            follow_top_symlink=True, follow_child_symlinks=True,
    ) == [
        'files/B/B/x',
        'files/B/B/y',
        'files/B/B',
        'files/A/x',
        'files/A/y',
        'files/A',
        'files/B/x',
        'files/B/y',
        'files/B',
    ]
    assert recurse_wrapper(tmp_path, 'files/A/B',
            realpath=True, recurse=True,
            follow_top_symlink=True, follow_child_symlinks=False,
    ) == [
        'files/A/B/A',
        'files/B/B/x',
        'files/B/B/y',
        'files/B/B',
    ]
    assert recurse_wrapper(tmp_path, 'files',
            realpath=False, recurse=True,
            follow_top_symlink=True, follow_child_symlinks=True,
    ) == [
        'files/A/B/x',
        'files/A/B/y',
        'files/A/B',
        'files/A/x',
        'files/A/y',
        'files/A',
        'files/B/x',
        'files/B/y',
        'files/B',
        'files',
    ]
    assert recurse_wrapper(tmp_path, 'files',
            realpath=True, recurse=True,
            follow_top_symlink=True, follow_child_symlinks=True,
    ) == [
        'files/B/B/x',
        'files/B/B/y',
        'files/B/B',
        'files/A/x',
        'files/A/y',
        'files/A',
        'files/B/x',
        'files/B/y',
        'files/B',
        'files',
    ]
