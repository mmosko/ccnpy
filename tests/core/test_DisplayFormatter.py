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
import json


class DisplayFormatterTest(unittest.TestCase):
    def test_Packet(self):
        input="Packet(FH(1, 1, 435, array('B', [0, 0, 0]), 8), CO(NAME([TLV(1, 3, b'foo'), TLV(1, 3, b'bar')]), Timestamp('2019-10-11T01:02:03'), PLDTYP('MANIFEST'), Manifest(None, Node(NodeData(SubtreeSize(5000), None, None), 1, [HashGroup(None, Ptrs([HashValue('SHA256', b'581d0e63b9260ce0bd70e0bf05c923ad6dc5bc7a730a5d9395f4af3158453f4b')]))]), None)), {RsaSha256 keyid: HashValue('SHA256', b'6f76dd6161f9eff713d6f279e2290dc0745685d2d67672d95c62656a79f1ff3c'), pk: None, link: None, time: Timestamp('2019-06-30T22:33:49.506000')}, ValPld(b'9f192395e4360e2e299bddf4e5c577c684849e8af1ef64d8162a16de64481ef8cbe285b0c53a9c127a75a4bfb84870cef81568d964eeeb0640fc95209f2542af6f63577fd974363f45f794434a3b9385e30d633c7a874a87224f871b9925c5b2a3a5557b190c4edede2731364b988c4848c0a1d7eb71cd8ae3dc8c30c59d6603e5c9582f40bd7d688c0e0ef1158ba53bcbcc77571eaa7ef5f902a48e2465c1032cbda902050e9d810af97822ac3bd85077869bf069db3ea3dd00d7bf362ab9e616d3a784c1505985ffed8952c391e4f64b1e14f9ad1100991a9a4fc79f5b6bef35a8f1218497290b114e0c60d1f42dee4df93f674d148685bcdcf3e7d8ab2ced'))"
        pass

    def test_Timestamp(self):
        input="Timestamp('2019-10-11T01:02:03')"
        pass

    def test_Name(self):
        input="{NAME: [{TLV: {T: 1, L: 3, V: b'foo'}, {TLV: {T: 1, L: 3, V: b'bar'}]}"
        pass

