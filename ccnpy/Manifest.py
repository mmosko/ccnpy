import ccnpy


class Manifest(ccnpy.ContentObject):
    def __init__(self, name=None, expiry_time=None, security_ctx=None, node=None):
        ccnpy.ContentObject.__init__(self, name=name, expiry_time=expiry_time)
        self._type_number = ccnpy.TlvType.T_MANIFEST

        self._security_ctx = security_ctx
        self._node = node

    @classmethod
    def deserialize(cls, tlv):
        # TODO: Finish
        return cls()

    def serialize(self):
        pass

    def security_ctx(self):
        return self._security_ctx

    def node(self):
        return self._node

