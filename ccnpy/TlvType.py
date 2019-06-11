

class TlvType:
    T_INTEREST = 0x0001
    T_OBJECT = 0x0002
    T_VALIDATION_ALG = 0x0003
    T_VALIDATION_PAYLOAD = 0x0004
    T_MANIFEST = 0x0005

    T_NAMESEGMENT = 0x0001
    T_NAME = 0x0000
    T_PAYLOAD = 0x0001
    T_KEYIDRESTR = 0x0002
    T_OBJHASHRESTR = 0x0003
    T_PAYLDTYPE = 0x0005
    T_EXPIRY = 0x0006
    T_RSA_SHA256 = 0x0004
    T_EC_SECP_256K1 = 0x0006
    T_PAD = 0x0FFE
    T_KEYID = 0x0009
    T_PUBLICKEYLOC = 0x000A
    T_LINK = 0x000D
    T_KEYLINK = 0x000E
    T_SIGTIME = 0x000F
    T_SHA_256 = 0x0001

    """
    superclass for objects that are TLV types
    """
    def __init__(self, type_number):
        self._type_number = type_number

    def type_number(self):
        return self._type_number
