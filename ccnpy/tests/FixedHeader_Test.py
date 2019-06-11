import unittest
import array

import ccnpy


class FixedHeader_Test(unittest.TestCase):
    def test_serialize(self):
        fh = ccnpy.FixedHeader(ver=1, packet_type=1, packet_length=0x0102, fields=[7, 8, 9], header_length=8)
        actual = fh.serialize()
        truth = array.array("B", [1, 1, 1, 2, 7, 8, 9, 8])
        self.assertEqual(actual, truth, "incorrect fixed header")

    def test_deserialize(self):
        wire_format = array.array("B", [1, 1, 1, 2, 7, 8, 9, 8])
        truth = ccnpy.FixedHeader(ver=1, packet_type=1, packet_length=0x0102, fields=[7, 8, 9], header_length=8)
        actual = ccnpy.FixedHeader.deserialize(wire_format)
        self.assertEqual(actual, truth, "incorrect fixed header")


