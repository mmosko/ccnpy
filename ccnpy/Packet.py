
import ccnpy


class Packet:
    def __init__(self, header, body, validation_alg=None, validation_payload=None):
        self._header = header
        self._body = body
        self._validation_alg = validation_alg
        self._validation_payload = validation_payload

    @classmethod
    def deserialize(cls, buffer):
        header = body = val_alg = val_payload = None

        offset = 0
        header = ccnpy.FixedHeader.deserialize(buffer)
        offset += header.header_length()

        while offset < len(buffer):
            tlv = ccnpy.Tlv.deserialize(buffer)
            offset += len(tlv)

            if tlv.type() == ccnpy.TlvType.T_OBJECT:
                assert body is None
                body = ccnpy.ContentObject.deserialize(tlv)
            elif tlv.type() == ccnpy.TlvType.T_INTEREST:
                assert body is None
                body = ccnpy.Interest.deserialize(tlv)
            elif tlv.type() == ccnpy.TlvType.T_VALIDATION_ALG:
                assert val_alg is None
                val_alg = ccnpy.ValidationAlg.deserialize(tlv)
            elif tlv.type() == ccnpy.TlvType.T_VALIDATION_ALG:
                assert val_alg is not None
                assert val_payload is None
                val_payload = ccnpy.ValidationPayload.deserialize(tlv)
            else:
                raise RuntimeError("Unsupported packet TLV type %r" % tlv.type())

        # TODO:  Finish
        return cls(header=None, body=None)

    def header(self):
        return self._header

    def body(self):
        return self._body

    def validation_alg(self):
        return self._validation_alg

    def validation_payload(self):
        return self._validation_payload
