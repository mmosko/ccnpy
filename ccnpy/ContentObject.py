import ccnpy


class ContentObject(ccnpy.TlvType):
    def __init__(self, name=None, payload_type=None, payload=None, expiry_time=None):
        ccnpy.TlvType.__init__(self, ccnpy.TlvType.T_OBJECT)

        self._name = name
        self._payload_type = payload_type
        self._payload = payload
        self._expiry_time = expiry_time
        self._tlv = ccnpy.Tlv(self.type_number(), [self._name,
                                                   self._expiry_time,
                                                   self._payload_type,
                                                   self._payload])

    def name(self):
        return self._name

    def payload_type(self):
        if self._payload_type is not None:
            return self._payload_type.value()
        return None

    def payload(self):
        if self._payload is not None:
            return self._payload.value()
        return None

    def expiry_time(self):
        return self._expiry_time

    @classmethod
    def deserialize(cls, tlv):
        if tlv.type() != ccnpy.TlvType.T_OBJECT:
            raise RuntimeError("Incorrect TLV type %r must be T_OBJECT")

        name = payload_type = payload = expiry_time = None
        offset = 0
        while offset < tlv.length():
            inner_tlv = ccnpy.Tlv.deserialize(tlv.value[offset:])
            offset += len(inner_tlv)

            if inner_tlv.type() == ccnpy.TlvType.T_NAME:
                assert name is None
                name = ccnpy.Name.deserialize(inner_tlv)
            elif inner_tlv.type() == ccnpy.TlvType.T_PAYLDTYPE:
                assert payload_type is None
                payload_type = inner_tlv
            elif inner_tlv.type() == ccnpy.TlvType.T_PAYLOAD:
                assert payload is None
                payload = inner_tlv
            elif inner_tlv.type() == ccnpy.TlvType.T_EXPIRY:
                assert expiry_time is None
                expiry_time = ccnpy.ExpiryTime.deserialize(inner_tlv)
            else:
                raise ValueError("Unsupported ContentObject TLV %r" % inner_tlv.type())

        return cls(name=name, payload_type=payload_type, payload=payload, expiry_time=expiry_time)

    def serialize(self):
        return self._tlv.serialize()

