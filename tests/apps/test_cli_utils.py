#  Copyright 2024 Marc Mosko
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import argparse
import os
import tempfile

from array import array

from ccnpy.apps.cli_utils import add_encryption_cli_args
from ccnpy.flic.tlvs.KdfInfo import KdfInfo
from ccnpy.flic.tlvs.KeyNumber import KeyNumber
from tests.MockKeys import private_key_pem
from tests.ccnpy_testcase import CcnpyTestCase


class CliUtilsTest(CcnpyTestCase):
    test_key_file = None
    test_data_file = None
    file_data = array("B", 5000 * [0])
    test_out_dir = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.test_key_file = tempfile.NamedTemporaryFile(delete=False)
        cls.test_key_file.write(private_key_pem)
        cls.test_key_file.close()

        cls.test_data_file = tempfile.NamedTemporaryFile(delete=False)
        cls.test_data_file.write(cls.file_data)
        cls.test_data_file.close()

        cls.test_out_dir = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.test_key_file.name)
        os.unlink(cls.test_data_file.name)
        cls.test_out_dir.cleanup()

    def setUp(self):
        self.parser = argparse.ArgumentParser()
        add_encryption_cli_args(self.parser)

    def _set_values(self):
        a = [
            '-k', self.test_key_file.name,
            # '--key_pass', None,
            # '--wrap_key', None,
            # '--wrap_pass', None,
            '--enc-key', '0x000102030405060708090a0b0c0d0e0f',
            '--aes-mode', 'GCM',
            '--key-num', '88',
            '--salt', '0x1234',
            '--kdf', 'hkdf-sha256',
            '--kdf-info', 'deadbeef',
            '--kdf-salt', '0x98999a'
        ]

        args = self.parser.parse_args(args=a)
        return args

    def test_enc_key_0x(self):
        a = [
            '--enc-key', '0x000102030405060708090a0b0c0d0e0f',
        ]

        args = self.parser.parse_args(args=a)
        self.assertEqual(
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f', args.enc_key)

    def test_enc_key_hex(self):
        a = [
            '--enc-key', '000102030405060708090a0b0c0d0e0f',
        ]

        args = self.parser.parse_args(args=a)
        self.assertEqual(
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f', args.enc_key)

    def test_key_num(self):
        a = [
            '--key-num', '77',
        ]
        args = self.parser.parse_args(args=a)
        self.assertEqual(KeyNumber(77), args.key_num)

    def test_key_num_hex(self):
        a = [
            '--key-num', '0x77',
        ]
        args = self.parser.parse_args(args=a)
        self.assertEqual(KeyNumber(0x77), args.key_num)

    def test_salt(self):
        a = [
            '--salt', '0x010203',
        ]
        args = self.parser.parse_args(args=a)
        self.assertEqual(0x010203, args.salt)

    def test_kdf_salt(self):
        a = [
            '--kdf-salt', '0x010203',
        ]
        args = self.parser.parse_args(args=a)
        self.assertEqual(0x010203, args.kdf_salt)

    def test_kdf_info(self):
        a = [
            '--kdf-info', '0x010203',
        ]
        args = self.parser.parse_args(args=a)
        self.assertEqual(KdfInfo('0x010203'), args.kdf_info)
