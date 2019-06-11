import ccnpy


class HashValue(ccnpy.TlvType):

    def __init__(self, hash_algorithm, value):
        """

        :param hash_algorithm: The method used to compute the hash (e.g. T_SHA_256)
        :param value: The hash value
        """
        ccnpy.TlvType.__init__(self, hash_algorithm)
        self._value = value
        self._tlv = ccnpy.Tlv(self.type_number(), self._value)

    def hash_algorithm(self):
        return self.type_number()

    def value(self):
        return self._value

    def serialize(self):
        return self._tlv.serialize()

    @classmethod
    def deserialize(cls, tlv):
        # TODO: Finish
        pass

    @classmethod
    def create_sha256(cls, value):
        return cls(ccnpy.TlvType.T_SHA_256, value)
