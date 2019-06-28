#  Copyright 2019 Marc Mosko
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

import unittest
import ccnpy.apps


class test_manifest_writer(unittest.TestCase):
    class Args:
        pass

    def _create_args(self):
        args=test_manifest_writer.Args()
        args.filename='foobar',
        args.key_file='rsa_key.pem'
        args.max_size=1500
        args.name='ccnx:/foo/bar'
        args.root_flag=False,
        args.tree_degree=4
        args.out_dir='.'
        args.locator=None
        args.root_expiry='2019-10-11T01:02:03+00:00'
        args.node_expiry=None
        args.data_expiry='2019-10-11T01:02:03+00:00'
        args.enc_key=None
        args.key_num=None
        return args

    def test_calculate_max_pointers(self):
        args = self._create_args()

        mw = ccnpy.apps.ManifestWriter(args)
        #print(mw)
        mw._calculate_max_pointers()

