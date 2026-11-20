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

"""
Some unit tests for HostKeys.
"""

from base64 import decodebytes
from binascii import hexlify
import os
import unittest

import paramiko

from ._util import _support


test_hosts_file = """\
secure.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA1PD6U2/TVxET6lkpKhOk5r\
9q/kAYG6sP9f5zuUYP8i7FOFp/6ncCEbbtg/lB+A3iidyxoSWl+9jtoyyDOOVX4UIDV9G11Ml8om3\
D+jrpI9cycZHqilK0HmxDeCuxbwyMuaCygU9gS2qoRvNLWZk70OpIKSSpBo0Wl3/XUmz9uhc=
broken.example.com ssh-rsa AAAA
happy.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31M\
BGQ3GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW\
5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M=
modern.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKHEChAIxsh2hr8Q\
+Ea1AAHZyfEB2elEc2YgduVzBtp+
curvy.example.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz\
dHAyNTYAAABBBAa+pY7djSpbg5viAcZhPt56AO3U3Sd7h7dnlUp0EjfDgyYHYQxl2QZ4JGgfwR5iv9\
T9iRZjQzvJd5s+kBAZtpk=
"""

test_hosts_file_tabs = """\
secure.example.com\tssh-rsa\tAAAAB3NzaC1yc2EAAAABIwAAAIEA1PD6U2/TVxET6lkpKhOk5r\
9q/kAYG6sP9f5zuUYP8i7FOFp/6ncCEbbtg/lB+A3iidyxoSWl+9jtoyyDOOVX4UIDV9G11Ml8om3\
D+jrpI9cycZHqilK0HmxDeCuxbwyMuaCygU9gS2qoRvNLWZk70OpIKSSpBo0Wl3/XUmz9uhc=
happy.example.com\tssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31M\
BGQ3GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW\
5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M=
modern.example.com\tssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAAIKHEChAIxsh2hr8Q\
+Ea1AAHZyfEB2elEc2YgduVzBtp+
curvy.example.com\tecdsa-sha2-nistp256\tAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbml\
zdHAyNTYAAABBBAa+pY7djSpbg5viAcZhPt56AO3U3Sd7h7dnlUp0EjfDgyYHYQxl2QZ4JGgfwR5iv\
9T9iRZjQzvJd5s+kBAZtpk=
"""

keyblob = b"""\
AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31MBGQ3GQ/Fc7SX6gkpXkwcZryoi4k\
NFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW5ymME3bQ4J/k1IKxCtz/bAlAqFgK\
oc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M="""


class HostKeysTest(unittest.TestCase):
    def setUp(self):
        with open("hostfile.temp", "w") as f:
            f.write(test_hosts_file)

    def tearDown(self):
        os.unlink("hostfile.temp")

    def test_load(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        assert len(hostdict) == 4
        self.assertEqual(1, len(list(hostdict.values())[0]))
        self.assertEqual(1, len(list(hostdict.values())[1]))
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-rsa"].get_fingerprint()
        ).upper()
        self.assertEqual(b"E6684DB30E109B67B70FF1DC5C7F1363", fp)

    def test_add(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        hh = "|1|BMsIC6cUIP2zBuXR3t2LRcJYjzM=|hpkJMysjTk/+zzUUzxQEa2ieq6c="
        key = paramiko.RSAKey(data=decodebytes(keyblob))
        hostdict.add(hh, "ssh-rsa", key)
        assert len(hostdict) == 5
        x = hostdict["foo.example.com"]
        fp = hexlify(x["ssh-rsa"].get_fingerprint()).upper()
        self.assertEqual(b"7EC91BB336CB6D810B124B1353C32396", fp)
        self.assertTrue(hostdict.check("foo.example.com", key))

    def test_dict(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        self.assertTrue("secure.example.com" in hostdict)
        self.assertTrue("not.example.com" not in hostdict)
        self.assertTrue("secure.example.com" in hostdict)
        self.assertTrue("not.example.com" not in hostdict)
        x = hostdict.get("secure.example.com", None)
        self.assertTrue(x is not None)
        fp = hexlify(x["ssh-rsa"].get_fingerprint()).upper()
        self.assertEqual(b"E6684DB30E109B67B70FF1DC5C7F1363", fp)
        assert list(hostdict) == hostdict.keys()
        assert len(list(hostdict)) == len(hostdict.keys()) == 4

    def test_dict_set(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        key = paramiko.RSAKey(data=decodebytes(keyblob))
        key_ed25519 = paramiko.Ed25519Key.from_private_key_file(
            _support("ed25519.key")
        )
        hostdict["secure.example.com"] = {
            "ssh-rsa": key,
            "ssh-ed25519": key_ed25519,
        }
        hostdict["fake.example.com"] = {}
        hostdict["fake.example.com"]["ssh-rsa"] = key

        assert len(hostdict) == 5
        self.assertEqual(2, len(list(hostdict.values())[0]))
        self.assertEqual(1, len(list(hostdict.values())[1]))
        self.assertEqual(1, len(list(hostdict.values())[2]))
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-rsa"].get_fingerprint()
        ).upper()
        self.assertEqual(b"7EC91BB336CB6D810B124B1353C32396", fp)
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-ed25519"].get_fingerprint()
        ).upper()
        self.assertEqual(b"B3D522AAF9755EE8CD0EEA02B929A280", fp)

    def test_delitem(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        target = "happy.example.com"
        hostdict[target]  # will KeyError if not present
        del hostdict[target]
        try:
            hostdict[target]
        except KeyError:
            pass  # Good
        else:
            assert False, "Entry was not deleted from HostKeys on delitem!"

    def test_entry_delitem(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        target = "happy.example.com"
        entry = hostdict[target]
        key_type_list = [key_type for key_type in entry]
        for key_type in key_type_list:
            del entry[key_type]

        # will KeyError if not present
        for key_type in key_type_list:
            try:
                del entry[key_type]
            except KeyError:
                pass  # Good
            else:
                assert False, "Key was not deleted from Entry on delitem!"


class HostKeysTabsTest(HostKeysTest):
    def setUp(self):
        with open("hostfile.temp", "w") as f:
            f.write(test_hosts_file_tabs)


# @cert-authority / @revoked coverage.  The four input shapes below are the
# test matrix: plain lines only, wildcard cert-authority, revoked, and hashed
# host names carrying markers.
_HASH_SALT = "BMsIC6cUIP2zBuXR3t2LRcJYjzM="

_plain_lines = {
    line.split(" ")[0]: line for line in test_hosts_file.splitlines() if line
}


def _marker_line(marker, hostnames, source_line):
    """Re-use the key data of ``source_line`` under a marker and new names."""
    _, key_type, key_data = source_line.split(" ")
    return "@{} {} {} {}".format(marker, hostnames, key_type, key_data)


_cert_wildcard_line = _marker_line(
    "cert-authority", "*.corp.example.com", _plain_lines["modern.example.com"]
)
_cert_hashed_line = _marker_line(
    "cert-authority",
    paramiko.HostKeys.hash_host("builder.example.com", _HASH_SALT),
    _plain_lines["curvy.example.com"],
)
_revoked_plain_line = _marker_line(
    "revoked", "revoked.example.com", _plain_lines["happy.example.com"]
)
_revoked_hashed_line = _marker_line(
    "revoked",
    paramiko.HostKeys.hash_host("revoked.example.com", _HASH_SALT),
    _plain_lines["happy.example.com"],
)

# A mixed file in which marker lines sit in the middle: if loading aborted at
# a marker line, every plain line below it would be missing.
test_hosts_file_markers = "\n".join(
    [
        _plain_lines["secure.example.com"],
        _cert_wildcard_line,
        _plain_lines["happy.example.com"],
        _revoked_plain_line,
        _cert_hashed_line,
        _revoked_hashed_line,
        _plain_lines["curvy.example.com"],
    ]
)


class HostKeysMarkersTest(unittest.TestCase):
    filename = "hostfile.markers.temp"

    def setUp(self):
        with open(self.filename, "w") as f:
            f.write(test_hosts_file_markers)

    def tearDown(self):
        os.unlink(self.filename)

    def _load_text(self, text):
        with open(self.filename, "w") as f:
            f.write(text)
        return paramiko.HostKeys(self.filename)

    def test_plain_lines_keep_existing_readings(self):
        # Matrix group 1: plain lines only, unchanged behaviour.
        hostdict = self._load_text(test_hosts_file)
        assert len(hostdict) == 4
        for host in (
            "secure.example.com",
            "happy.example.com",
            "modern.example.com",
            "curvy.example.com",
        ):
            entry = hostdict.lookup(host)
            self.assertIsNotNone(entry)
            self.assertNotIn("revoked", entry.markers.values())
            self.assertFalse(hostdict.is_revoked(host))
        self.assertTrue(
            hostdict.check(
                "happy.example.com",
                paramiko.RSAKey(data=decodebytes(keyblob)),
            )
        )
        self.assertEqual(hostdict.revoked_keys(), [])

    def test_mixed_file_loads_through_marker_lines(self):
        hostdict = paramiko.HostKeys(self.filename)
        # 5 offerable host names: revoked ones stay out of the mapping.
        assert len(hostdict) == 5
        # Plain lines before and after the marker lines are all effective.
        for host in (
            "secure.example.com",
            "happy.example.com",
            "curvy.example.com",
        ):
            entry = hostdict.lookup(host)
            self.assertIsNotNone(entry, host)
            self.assertTrue(hostdict.check(host, entry[entry.keys()[0]]))
        # The last line of the file took effect.
        self.assertIsNotNone(hostdict["curvy.example.com"])

    def test_cert_authority_wildcard_is_queryable(self):
        # Matrix group 2: wildcard CA trust-anchor line.
        hostdict = paramiko.HostKeys(self.filename)
        entry = hostdict.lookup("node7.corp.example.com")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.markers, {"ssh-ed25519": "cert-authority"})
        self.assertIn("ssh-ed25519", entry.keys())
        # Trust-anchor lines are not "revoked" merely because they are markers.
        self.assertFalse(hostdict.is_revoked("node7.corp.example.com"))
        # A host matching no line is still unknown.
        self.assertIsNone(hostdict.lookup("node7.other.example.com"))

    def test_revoked_is_distinguishable_from_unknown(self):
        # Matrix group 3: revoked line.
        hostdict = paramiko.HostKeys(self.filename)
        revoked_key = paramiko.RSAKey(data=decodebytes(keyblob))
        self.assertIsNone(hostdict.lookup("revoked.example.com"))
        self.assertTrue(hostdict.is_revoked("revoked.example.com"))
        self.assertFalse(hostdict.check("revoked.example.com", revoked_key))
        self.assertIn("revoked.example.com", hostdict.revoked_keys())
        # Unknown host: no entry, and not revoked either.
        self.assertIsNone(hostdict.lookup("nowhere.example.com"))
        self.assertFalse(hostdict.is_revoked("nowhere.example.com"))

    def test_hashed_marker_lines_match_plain_name_readings(self):
        # Matrix group 4: markers on |1| hashed host names behave the same as
        # the plain-name forms (same key type offered, same marker recorded).
        hostdict = paramiko.HostKeys(self.filename)
        hashed_cert = hostdict.lookup("builder.example.com")
        self.assertIsNotNone(hashed_cert)
        self.assertEqual(
            hashed_cert.markers, {"ecdsa-sha2-nistp256": "cert-authority"}
        )
        plain_cert = self._load_text(
            _marker_line(
                "cert-authority",
                "builder.example.com",
                _plain_lines["curvy.example.com"],
            )
        ).lookup("builder.example.com")
        self.assertIsNotNone(plain_cert)
        self.assertEqual(
            list(hashed_cert.markers.values()),
            list(plain_cert.markers.values()),
        )
        self.assertEqual(hashed_cert.keys(), plain_cert.keys())

        # Revoked hashed line: same verdict as the plain revoked line.
        self.assertTrue(hostdict.is_revoked("revoked.example.com"))
        self.assertIsNone(hostdict.lookup("revoked.example.com"))

    def test_revoked_key_rejected_even_with_plain_entry(self):
        hostdict = self._load_text(
            "{}\n{}\n".format(
                _plain_lines["happy.example.com"],
                _marker_line(
                    "revoked",
                    "happy.example.com",
                    _plain_lines["happy.example.com"],
                ),
            )
        )
        key = paramiko.RSAKey(data=decodebytes(keyblob))
        self.assertFalse(hostdict.check("happy.example.com", key))
        self.assertTrue(hostdict.is_revoked("happy.example.com"))

    def test_unknown_marker_and_invalid_lines_are_skipped(self):
        text = "\n".join(
            [
                "@unsupported-marker ghost.example.com ssh-rsa AAAA",
                "broken.example.com ssh-rsa AAAA",
                _plain_lines["secure.example.com"],
            ]
        )
        hostdict = self._load_text(text)
        assert len(hostdict) == 1
        self.assertIsNotNone(hostdict.lookup("secure.example.com"))
        self.assertIsNone(hostdict.lookup("ghost.example.com"))

    def test_entry_to_line_keeps_marker(self):
        for line in (
            _cert_wildcard_line,
            _revoked_plain_line,
            _cert_hashed_line,
            _revoked_hashed_line,
        ):
            entry = paramiko.hostkeys.HostKeyEntry.from_line(line)
            self.assertEqual(entry.to_line().strip(), line)
        plain = paramiko.hostkeys.HostKeyEntry.from_line(
            _plain_lines["secure.example.com"]
        )
        self.assertIsNone(plain.marker)
        self.assertEqual(
            plain.to_line().strip(), _plain_lines["secure.example.com"]
        )

    def test_save_after_add_keeps_marker_lines(self):
        # Mirrors AutoAddPolicy: add the unknown host, then archive the whole
        # file back out, then feed it to the next round.
        hostdict = paramiko.HostKeys(self.filename)
        new_key = paramiko.RSAKey(data=decodebytes(keyblob))
        hostdict.add("new.example.com", "ssh-rsa", new_key)
        hostdict.save(self.filename)

        with open(self.filename) as f:
            written = [line.strip() for line in f if line.strip()]

        original = test_hosts_file_markers.splitlines()
        self.assertEqual(written[:-1], original)
        self.assertEqual(
            written[-1],
            "new.example.com ssh-rsa {}".format(new_key.get_base64()),
        )

        reloaded = paramiko.HostKeys(self.filename)
        self.assertIsNotNone(reloaded.lookup("new.example.com"))
        self.assertTrue(reloaded.is_revoked("revoked.example.com"))
        self.assertEqual(
            reloaded.lookup("node7.corp.example.com").markers,
            {"ssh-ed25519": "cert-authority"},
        )
        self.assertIsNone(reloaded.lookup("revoked.example.com"))

    def test_sshclient_entry_loads_mixed_file(self):
        client = paramiko.SSHClient()
        client.load_host_keys(self.filename)
        keys = client.get_host_keys()
        self.assertIsNotNone(keys.lookup("secure.example.com"))
        self.assertIsNotNone(keys.lookup("node7.corp.example.com"))
        self.assertTrue(keys.is_revoked("revoked.example.com"))
        self.assertIsNone(keys.lookup("revoked.example.com"))
