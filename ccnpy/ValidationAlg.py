import ccnpy


class ValidationAlg(ccnpy.TlvType):
    def __init__(self, algorithm_id):
        """
        """
        ccnpy.TlvType.__init__(self, algorithm_id)
        pass

    @classmethod
    def deserialize(cls, tlv):
        pass

    def serialize(self):
        pass


class RsaSha256(ValidationAlg):
    def __init(self):
        ValidationAlg.__init__(self, ccnpy.TlvType.T_RSA_SHA256)

    @classmethod
    def deserialize(cls, tlv):
        pass

    def serialize(self):
        pass
