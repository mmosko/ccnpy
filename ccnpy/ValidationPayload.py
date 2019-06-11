import ccnpy


class ValidationPayload(ccnpy.TlvType):
    def __init__(self, payload):
        """
        """
        ccnpy.TlvType.__init__(self, ccnpy.TlvType.T_VALIDATION_PAYLOAD)
        self._payload = payload
        self._tlv = ccnpy.Tlv(self.type_number(), self._payload)

    def __eq__(self, other):
        return self.payload() == other.payload()

    @classmethod
    def deserialize(cls, tlv):
        if tlv.type() != ccnpy.TlvType.T_VALIDATION_PAYLOAD:
            raise RuntimeError("Incorrect TLV type %r" % tlv.type())

        return cls(tlv.value())

    def serialize(self):
        return self._tlv.serialize()

    def payload(self):
        return self._payload
