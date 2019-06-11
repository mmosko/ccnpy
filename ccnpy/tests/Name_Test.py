import unittest
import array
import ccnpy


class Name_Test(unittest.TestCase):
    def test_from_uri(self):
        uri='ccnx:/apple/banana/cherry/durian'
        name = ccnpy.Name.from_uri(uri)
        print(name)
        wire_format = name.serialize()
        truth = array.array('B', [0, 0, 0, 39,
                                  0, 1, 0, 5, 97, 112, 112, 108, 101,
                                  0, 1, 0, 6, 98, 97, 110, 97, 110, 97,
                                  0, 1, 0, 6, 99, 104, 101, 114, 114, 121,
                                  0, 1, 0, 6, 100, 117, 114, 105, 97, 110])

        self.assertEqual(wire_format, truth, 'incorrect wire format')

    def test_components(self):
        uri='ccnx:/apple/banana/cherry/durian'
        name = ccnpy.Name.from_uri(uri)
        self.assertEqual(name.count(), 4)
        self.assertEqual(name[0], 'apple')
        self.assertEqual(name[1], 'banana')
        self.assertEqual(name[2], 'cherry')
        self.assertEqual(name[3], 'durian')
