import unittest
import array
import ccnpy


class ValidationPayload_Test(unittest.TestCase):

    def test_serialize(self):
        payload = array.array("B", [1, 2, 3, 4, 5, 6])
        vp = ccnpy.ValidationPayload(payload)
        expected = array.array("B", [0, 4, 0, 6, 1, 2, 3, 4, 5, 6])
        actual = vp.serialize()
        self.assertEqual(expected, actual)

    def test_deserialize(self):
        payload = array.array("B", [1, 2, 3, 4, 5, 6])
        tlv = ccnpy.Tlv(ccnpy.TlvType.T_VALIDATION_PAYLOAD, payload)
        expected = ccnpy.ValidationPayload(payload)
        actual = ccnpy.ValidationPayload.deserialize(tlv)
        self.assertEqual(expected, actual)