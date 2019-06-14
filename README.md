# Pure Python CCNx 1.0

ccnpy is a pure python implementation of the CCNx 1.0
protocols (RFC xxxx and RFC yyyy).


## dependencies

```python3 -m pip install cryptography crc32c```

# Implementation nodes


## Serialization and Deserialization
The class methods `deserialize(buffer)` 
take a byte array (array.array("B", ...)).  They are found in `ccnpy.Packet.deserialize(buffer)`
and `ccnpy.FixedHeader.deserialize(buffer)` and `ccnpy.Tlv.deserialize(buffer)` 
and `ccnpy.Link.deserialize(buffer)`.  Other
classes work at the TLV level via the class method `parse(tlv)`.

Typically, all one needs to do is call `ccnpy.Packet.deserialize(buffer)` or
`ccnpy.Packet.load(filename)` and everthing else is done automatically.

The `serialize()` methods always return a byte array (array.array("B", ...)).
Typically, all one needs to do is call `ccnpy.Packet.serialize()` or `ccnpy.Packet.save(filename)`.
