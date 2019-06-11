import ccnpy


class ValidationAlg(ccnpy.TlvType):
    def __init__(self):
        """
        """
        ccnpy.TlvType.__init__(self, 0)
        pass

    @classmethod
    def deserialize(cls, tlv):
        pass

    def serialize(self):
        pass
