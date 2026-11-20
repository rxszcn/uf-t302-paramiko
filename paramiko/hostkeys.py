# Copyright (C) 2006-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.


import binascii
import os
import re
from base64 import decodebytes, encodebytes
from collections.abc import MutableMapping
from fnmatch import fnmatchcase
from hashlib import sha1
from hmac import HMAC

from paramiko.pkey import PKey, UnknownKeyType
from paramiko.ssh_exception import SSHException
from paramiko.util import b, constant_time_bytes_eq, get_logger, u


# Line markers defined by OpenSSH's known_hosts format, without the leading
# "@".  A marked line is "@<marker> <hostnames> <keytype> <base64>".
MARKER_CERT_AUTHORITY = "cert-authority"
MARKER_REVOKED = "revoked"
SUPPORTED_MARKERS = (MARKER_CERT_AUTHORITY, MARKER_REVOKED)


def _is_pattern(hostname):
    """
    True if ``hostname`` is a shell-style wildcard host pattern rather than a
    literal name or an OpenSSH ``|1|`` hashed name.
    """
    if hostname.startswith("|1|"):
        return False
    return ("*" in hostname) or ("?" in hostname)


class HostKeys(MutableMapping):
    """
    Representation of an OpenSSH-style "known hosts" file.  Host keys can be
    read from one or more files, and then individual hosts can be looked up to
    verify server keys during SSH negotiation.

    A `.HostKeys` object can be treated like a dict; any dict lookup is
    equivalent to calling `lookup`.

    Besides plain ``hostnames keytype base64`` lines, the loader understands
    the OpenSSH line markers ``@cert-authority`` and ``@revoked``.  A
    ``@cert-authority`` line marks the key as a CA trust anchor and remains
    visible through `lookup` (wildcard host patterns such as
    ``*.example.com`` are supported), while a ``@revoked`` line records a key
    that must never be accepted.  Revoked entries are kept in the mapping (so
    that `save` can write them back), but they are excluded from `lookup`
    results and therefore never satisfy `check`.

    .. versionadded:: 1.5.3
    """

    def __init__(self, filename=None):
        """
        Create a new HostKeys object, optionally loading keys from an OpenSSH
        style host-key file.

        :param str filename: filename to load host keys from, or ``None``
        """
        # emulate a dict of { hostname: { keytype: PKey } }
        self._entries = []
        if filename is not None:
            self.load(filename)

    def add(self, hostname, keytype, key):
        """
        Add a host key entry to the table.  Any existing entry for a
        ``(hostname, keytype)`` pair will be replaced.

        Only plain entries are replaced: ``@cert-authority`` and ``@revoked``
        lines loaded from a file are never overwritten by `add`, so an
        AutoAddPolicy write-back keeps the markers it started with.

        :param str hostname: the hostname (or IP) to add
        :param str keytype: key type (in ``"ssh-<type>"`` format)
        :param .PKey key: the key to add
        """
        for e in self._entries:
            if (
                e.marker is None
                and e.key is not None
                and (hostname in e.hostnames)
                and (e.key.get_name() == keytype)
            ):
                e.key = key
                return
        self._entries.append(HostKeyEntry([hostname], key))

    def load(self, filename):
        """
        Read a file of known SSH host keys, in the format used by OpenSSH.
        This type of file unfortunately doesn't exist on Windows, but on
        posix, it will usually be stored in
        ``os.path.expanduser("~/.ssh/known_hosts")``.

        If this method is called multiple times, the host keys are merged,
        not cleared.  So multiple calls to `load` will just call `add`,
        replacing any existing entries and adding new ones.

        Lines carrying the ``@cert-authority`` or ``@revoked`` markers are
        parsed and preserved.  Lines that cannot be parsed (including lines
        with an unrecognized ``@`` marker) are skipped silently, matching the
        long-standing behaviour for invalid lines.

        :param str filename: name of the file to read host keys from

        :raises: ``IOError`` -- if there was an error reading the file
        """
        with open(filename, "r") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if (len(line) == 0) or (line[0] == "#"):
                    continue
                try:
                    entry = HostKeyEntry.from_line(line, lineno)
                except (SSHException, InvalidHostKey, UnknownHostKeyMarker):
                    continue
                if entry is not None:
                    # Drop hostnames already covered by an identical plain
                    # entry.  Marked entries are never de-duplicated this way:
                    # their hostnames may be wildcard or hashed patterns, and
                    # dropping them would lose the trust/revocation semantics.
                    if entry.marker is None:
                        _hostnames = list(entry.hostnames)
                        for h in _hostnames:
                            if not _is_pattern(h) and self.check(h, entry.key):
                                entry.hostnames.remove(h)
                    if len(entry.hostnames):
                        self._entries.append(entry)

    def save(self, filename):
        """
        Save host keys into a file, in the format used by OpenSSH.  The order
        of keys in the file will be preserved when possible (if these keys were
        loaded from a file originally).  The single exception is that combined
        lines will be split into individual key lines, which is arguably a bug.

        ``@cert-authority`` and ``@revoked`` markers are written back verbatim,
        so a load/save round trip keeps the trust anchors and the revocation
        list intact.

        :param str filename: name of the file to write

        :raises: ``IOError`` -- if there was an error writing the file

        .. versionadded:: 1.6.1
        """
        with open(filename, "w") as f:
            for e in self._entries:
                line = e.to_line()
                if line:
                    f.write(line)

    def lookup(self, hostname):
        """
        Find a hostkey entry for a given hostname or IP.  If no entry is found,
        ``None`` is returned.  Otherwise a dictionary of keytype to key is
        returned.

        Revoked entries are deliberately omitted: ``None`` from this method
        means "no acceptable key", and `is_revoked` distinguishes a host whose
        key was revoked from one that is simply unknown.  ``@cert-authority``
        entries are included (wildcard host patterns are matched), and the
        ``markers`` member of the returned mapping exposes the marker that was
        loaded for each key type.

        :param str hostname: the hostname (or IP) to lookup
        :return: dict of `str` -> `.PKey` keys associated with this host
            (or ``None``)
        """

        class SubDict(MutableMapping):
            def __init__(self, hostname, entries, hostkeys):
                self._hostname = hostname
                self._entries = entries
                self._hostkeys = hostkeys

            @property
            def markers(self):
                """
                Mapping of key type to the marker loaded for it
                (``"cert-authority"``, or ``None`` for a plain entry).
                """
                return {
                    e.key.get_name(): e.marker
                    for e in self._entries
                    if e.key is not None
                }

            def __iter__(self):
                for k in self.keys():
                    yield k

            def __len__(self):
                return len(self.keys())

            def __delitem__(self, key):
                for e in list(self._entries):
                    if e.key.get_name() == key:
                        self._entries.remove(e)
                        break
                else:
                    raise KeyError(key)

            def __getitem__(self, key):
                for e in self._entries:
                    if e.key.get_name() == key:
                        return e.key
                raise KeyError(key)

            def __setitem__(self, key, val):
                for e in self._entries:
                    if e.key is None:
                        continue
                    if e.key.get_name() == key:
                        # replace
                        e.key = val
                        break
                else:
                    # add a new one
                    e = HostKeyEntry([hostname], val)
                    self._entries.append(e)
                    self._hostkeys._entries.append(e)

            def keys(self):
                return [
                    e.key.get_name()
                    for e in self._entries
                    if e.key is not None
                ]

        entries = []
        for e in self._entries:
            if e.marker != MARKER_REVOKED and self._hostname_matches(
                hostname, e
            ):
                entries.append(e)
        if len(entries) == 0:
            return None
        return SubDict(hostname, entries, self)

    def _hostname_matches(self, hostname, entry):
        """
        Tests whether ``hostname`` string matches given SubDict ``entry``.

        Matches exact names, OpenSSH ``|1|`` hashed names, and (for plain or
        ``@cert-authority`` entries) shell-style wildcard patterns such as
        ``*.example.com``.

        :returns bool:
        """
        for h in entry.hostnames:
            if h == hostname:
                return True
            if h.startswith("|1|"):
                if not hostname.startswith("|1|") and constant_time_bytes_eq(
                    self.hash_host(hostname, h), h
                ):
                    return True
            elif _is_pattern(h) and fnmatchcase(hostname, h):
                return True
        return False

    def is_revoked(self, hostname):
        """
        Return True if any key for ``hostname`` was explicitly revoked with a
        ``@revoked`` line in a loaded known_hosts file.

        This exists because `lookup` returns ``None`` both for an unknown host
        and for a host whose only known key is revoked; callers that need to
        tell the two apart (e.g. to warn instead of silently trusting) use this
        method.  ``hostname`` may be a real host name that matches a wildcard
        pattern, or the exact hashed ``|1|`` name.

        :param str hostname: the hostname (or IP) to check
        :return: True if the host has a matching ``@revoked`` entry
        """
        for e in self._entries:
            if e.marker == MARKER_REVOKED and self._hostname_matches(
                hostname, e
            ):
                return True
        return False

    def revoked_keys(self):
        """
        Return the hostname patterns of all ``@revoked`` entries, in file
        order.  Useful for auditing a loaded revocation list; the entries
        themselves are also written back by `save`.

        :return: list of `str` hostname patterns
        """
        ret = []
        for e in self._entries:
            if e.marker == MARKER_REVOKED:
                for h in e.hostnames:
                    if h not in ret:
                        ret.append(h)
        return ret

    def check(self, hostname, key):
        """
        Return True if the given key is associated with the given hostname
        in this dictionary.

        A key that appears on a matching ``@revoked`` line is always rejected,
        even if another (plain) entry would otherwise associate it with the
        host.

        :param str hostname: hostname (or IP) of the SSH server
        :param .PKey key: the key to check
        :return:
            ``True`` if the key is associated with the hostname; else ``False``
        """
        k = self.lookup(hostname)
        if k is None:
            return False
        host_key = k.get(key.get_name(), None)
        if host_key is None:
            return False
        if host_key.asbytes() != key.asbytes():
            return False
        for e in self._entries:
            if (
                e.marker == MARKER_REVOKED
                and e.key is not None
                and e.key.get_name() == key.get_name()
                and e.key.asbytes() == key.asbytes()
                and self._hostname_matches(hostname, e)
            ):
                return False
        return True

    def clear(self):
        """
        Remove all host keys from the dictionary.
        """
        self._entries = []

    def __iter__(self):
        for k in self.keys():
            yield k

    def __len__(self):
        return len(self.keys())

    def __getitem__(self, key):
        ret = self.lookup(key)
        if ret is None:
            raise KeyError(key)
        return ret

    def __delitem__(self, key):
        index = None
        for i, entry in enumerate(self._entries):
            if self._hostname_matches(key, entry):
                index = i
                break
        if index is None:
            raise KeyError(key)
        self._entries.pop(index)

    def __setitem__(self, hostname, entry):
        # don't use this please.
        if len(entry) == 0:
            self._entries.append(HostKeyEntry([hostname], None))
            return
        for key_type in entry.keys():
            found = False
            for e in self._entries:
                if (hostname in e.hostnames) and e.key.get_name() == key_type:
                    # replace
                    e.key = entry[key_type]
                    found = True
            if not found:
                self._entries.append(HostKeyEntry([hostname], entry[key_type]))

    def keys(self):
        ret = []
        for e in self._entries:
            # revoked entries stay in _entries so `save` can write them back,
            # but they are not offerable keys, so they are not "in" the mapping
            if e.marker == MARKER_REVOKED:
                continue
            for h in e.hostnames:
                if h not in ret:
                    ret.append(h)
        return ret

    def values(self):
        ret = []
        for k in self.keys():
            ret.append(self.lookup(k))
        return ret

    @staticmethod
    def hash_host(hostname, salt=None):
        """
        Return a "hashed" form of the hostname, as used by OpenSSH when storing
        hashed hostnames in the known_hosts file.

        :param str hostname: the hostname to hash
        :param str salt: optional salt to use when hashing
            (must be 20 bytes long)
        :return: the hashed hostname as a `str`
        """
        if salt is None:
            salt = os.urandom(sha1().digest_size)
        else:
            if salt.startswith("|1|"):
                salt = salt.split("|")[2]
            salt = decodebytes(b(salt))
        assert len(salt) == sha1().digest_size
        hmac = HMAC(salt, b(hostname), sha1).digest()
        hostkey = "|1|{}|{}".format(u(encodebytes(salt)), u(encodebytes(hmac)))
        return hostkey.replace("\n", "")


class InvalidHostKey(Exception):
    def __init__(self, line, exc):
        self.line = line
        self.exc = exc
        self.args = (line, exc)


class UnknownHostKeyMarker(Exception):
    """
    Raised internally when a known_hosts line starts with an ``@`` marker that
    paramiko does not implement.  `HostKeys.load` treats such lines the same
    way it treats any other unparseable line: it skips them.
    """


class HostKeyEntry:
    """
    Representation of a line in an OpenSSH-style "known hosts" file.

    ``marker`` is ``None`` for a plain entry, or one of
    ``"cert-authority"`` / ``"revoked"`` for a line that carried the
    corresponding OpenSSH ``@`` marker.  The marker is carried on the entry
    (rather than on `.HostKeys` as a side table) so that it survives
    `HostKeyEntry.from_line` / `HostKeyEntry.to_line`, and therefore survives
    a full load/save round trip of the known_hosts file.
    """

    def __init__(self, hostnames=None, key=None, marker=None):
        self.valid = (hostnames is not None) and (key is not None)
        self.hostnames = hostnames
        self.key = key
        self.marker = marker

    @classmethod
    def from_line(cls, line, lineno=None):
        """
        Parses the given line of text to find the names for the host,
        the type of key, and the key data. The line is expected to be in the
        format used by the OpenSSH known_hosts file. Fields are separated by a
        single space or tab.

        Lines are expected to not have leading or trailing whitespace.
        We don't bother to check for comments or empty lines.  All of
        that should be taken care of before sending the line to us.

        A leading ``@cert-authority`` or ``@revoked`` marker is recorded on
        the resulting entry; any other ``@`` marker raises
        `UnknownHostKeyMarker`, which `HostKeys.load` skips.

        :param str line: a line from an OpenSSH known_hosts file
        """
        log = get_logger("paramiko.hostkeys")
        marker = None
        stripped = line.lstrip()
        if stripped.startswith("@"):
            fields = re.split(" |\t", stripped)
            marker = fields[0][1:]
            if marker not in SUPPORTED_MARKERS:
                raise UnknownHostKeyMarker(marker)
            # Re-join the remainder so the normal 3-field parsing applies.
            line = " ".join(fields[1:])
        fields = re.split(" |\t", line)
        if len(fields) < 3:
            # Bad number of fields
            msg = "Not enough fields found in known_hosts in line {} ({!r})"
            log.info(msg.format(lineno, line))
            return None
        fields = fields[:3]

        names, key_type, key = fields
        names = names.split(",")

        # Decide what kind of key we're looking at and create an object
        # to hold it accordingly.
        try:
            # TODO: this grew organically and doesn't seem /wrong/ per se (file
            # read -> unicode str -> bytes for base64 decode -> decoded bytes);
            # but in Python 3 forever land, can we simply use
            # `base64.b64decode(str-from-file)` here?
            key_bytes = decodebytes(b(key))
        except binascii.Error as e:
            raise InvalidHostKey(line, e)

        try:
            return cls(
                names, PKey.from_type_string(key_type, key_bytes), marker
            )
        except UnknownKeyType:
            # TODO (backwards incompat): consider changing HostKeys API so this
            # just raises naturally and the exception is muted higher up in the
            # stack?
            log.info("Unable to handle key of type {}".format(key_type))
            return None

    def to_line(self):
        """
        Returns a string in OpenSSH known_hosts file format, or None if
        the object is not in a valid state.  A trailing newline is
        included.

        If `marker` was set, the ``@<marker> `` prefix is written back.
        """
        if self.valid:
            prefix = "@{} ".format(self.marker) if self.marker else ""
            return "{}{} {} {}\n".format(
                prefix,
                ",".join(self.hostnames),
                self.key.get_name(),
                self.key.get_base64(),
            )
        return None

    def __repr__(self):
        return "<HostKeyEntry {!r}: {!r}>".format(self.hostnames, self.key)
