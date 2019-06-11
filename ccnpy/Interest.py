import ccnpy


class Interest(ccnpy.TlvType):
    def __init__(self, name=None, key_id_restr=None, con_obj_hash_restr=None):
        """

        :param name:
        :param key_id_restr: KeyId Restriction
        :param con_obj_hash_restr: Content Object Hash Restriction
        :param lifetime: Interest Lifetime (default 4000 msec)
        :param hoplimit: Interest Hop Limit (default 255)
        """
        ccnpy.TlvType.__init__(self, ccnpy.TlvType.T_INTEREST)

        self._name = name
        self._keyidrestr = key_id_restr
        self._conobjhashrestr = con_obj_hash_restr

    @classmethod
    def deserialize(cls, tlv):
        pass

    def serialize(self):
        pass
    