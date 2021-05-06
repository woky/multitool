import types
from contextvars import copy_context
from typing import Tuple

import pytest

import lib


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
