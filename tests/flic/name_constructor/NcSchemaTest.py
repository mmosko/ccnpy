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


import array
import unittest

from ccnpy.core.Link import Link
from ccnpy.core.Tlv import Tlv
from ccnpy.flic.Locator import Locator
from ccnpy.flic.Locators import Locators
from ccnpy.flic.name_constructor.NcSchema import InterestDerivedSchema, DataDerivedSchema, PrefixSchema, \
    SegmentedSchema, HashSchema
from ccnpy.flic.name_constructor.SchemaType import SchemaType


class NcSchemaTest(unittest.TestCase):
    def test_interest_derived_schema_no_flags(self):
        s = InterestDerivedSchema()
        expected = array.array("B", [0, 1, 0, 0])
        wire_format = s.serialize()
        self.assertEqual(expected, wire_format)
        decoded = InterestDerivedSchema.parse(Tlv.deserialize(wire_format))
        self.assertEqual(s, decoded)

    def test_data_derived_schema_no_flags(self):
        s = DataDerivedSchema()
        expected = array.array("B", [0, 2, 0, 0])
        wire_format = s.serialize()
        self.assertEqual(expected, wire_format)
        decoded = DataDerivedSchema.parse(Tlv.deserialize(wire_format))
        self.assertEqual(s, decoded)

    def test_prefix_schema_no_flags(self):
        s = PrefixSchema(Locators([Locator(Link(name='ccnx:/a'))]))
        expected = array.array("B", [0, 3, 0, 17, 0, 3, 0, 13, 0, 2, 0, 9, 0, 0, 0, 5, 0, 1, 0, 1, 97])
        wire_format = s.serialize()
        self.assertEqual(expected, wire_format)
        decoded = PrefixSchema.parse(Tlv.deserialize(wire_format))
        self.assertEqual(s, decoded)

    def test_segmented_schema_no_flags(self):
        s = SegmentedSchema(Locators([Locator(Link('ccnx:/a'))]))
        expected = array.array("B", [0, 4, 0, 17, 0, 3, 0, 13, 0, 2, 0, 9, 0, 0, 0, 5, 0, 1, 0, 1, 97])
        wire_format = s.serialize()
        self.assertEqual(expected, wire_format)
        decoded = SegmentedSchema.parse(Tlv.deserialize(wire_format))
        self.assertEqual(s, decoded)

    def test_hash_schema_no_flags(self):
        s = HashSchema(Locators([Locator(Link('ccnx:/a'))]))
        expected = array.array("B", [0, 5, 0, 17, 0, 3, 0, 13, 0, 2, 0, 9, 0, 0, 0, 5, 0, 1, 0, 1, 97])
        wire_format = s.serialize()
        self.assertEqual(expected, wire_format)
        decoded = HashSchema.parse(Tlv.deserialize(wire_format))
        self.assertEqual(s, decoded)

    def test_schema_type_parse(self):
        self.assertEqual(SchemaType.HASHED, SchemaType.parse('Hashed'))
        self.assertEqual(SchemaType.PREFIX, SchemaType.parse('Prefix'))
        self.assertEqual(SchemaType.SEGMENTED, SchemaType.parse('Segmented'))
        with self.assertRaises(ValueError):
            SchemaType.parse('foo')
