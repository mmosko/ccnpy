import ccnpy


class ContentObject(ccnpy.TlvType):
    def __init__(self, name=None, content_type=None, payload=None, expiry_time=None):
        ccnpy.TlvType.__init__(self, ccnpy.TlvType.T_OBJECT)

        self._name = name
        self._content_type = content_type
        self._payload = payload
        self._expiry_time = expiry_time

    def name(self):
        return self._name

    def content_type(self):
        return self._content_type

    def payload(self):
        return self._payload

    def expiry_time(self):
        return self._expiry_time

    @classmethod
    def deserialize(cls, tlv):
        # TODO: finish
        return cls()

    def serialize(self):
        # TODO: finish
        return None

