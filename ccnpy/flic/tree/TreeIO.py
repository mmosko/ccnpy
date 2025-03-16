#  Copyright 2024 Marc Mosko
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os
import socket
from abc import ABC
from array import array
from pathlib import PurePath, Path
from typing import Optional, Dict

from .SizedPointer import SizedPointer
from ..tlvs.Locators import Locators
from ...core.ContentObject import ContentObject
from ...core.HashValue import HashValue
from ...core.Link import Link
from ...core.Name import Name
from ...core.Packet import Packet, PacketWriter, PacketReader
from ...crypto.Crc32c import Crc32cSigner
from ...crypto.Signer import Signer


class TreeIO:
    """
    A set of utility classes used for in-memory tree input/output

    """

    @staticmethod
    def get_link_name(name: Name) -> str:
        name_bytes = name.serialize().tobytes()
        return f'{name_bytes.hex()}.link'

    class DataBuffer:
        def __init__(self):
            self.buffer = array("B", [])
            self.count = 0

        def __repr__(self):
            return "{DataBuffer %r, %r}" % (self.count, self.buffer)

        def append(self, data):
            self.count += 1
            self.buffer.extend(data)

        def write(self, data):
            self.count += 1
            self.buffer.extend(data)

    class PacketMemoryReader(PacketReader):
        """
        An in-memory cache of packets that can be fetch by their content object hash
        """

        def __iter__(self):
            for packet in self.packets:
                yield packet

        def __getitem__(self, index):
            return self.packets[index]

        def __init__(self, packets):
            if isinstance(packets, TreeIO.PacketMemoryWriter):
                self.packets = packets.packets
                self.by_hash: Dict[str, Packet] = packets.by_hash
            else:
                self.packets = packets
                self.by_hash = {}
                for packet in self.packets:
                    # print("PacketInput: add key %r" % packet.content_object_hash())
                    self.by_hash[packet.content_object_hash()] = packet

        def get(self, name: Name, hash_restriction: HashValue, forwarding_hints: Optional[Locators] = None) -> Packet:
            # ccnx does not use forwarding hint
            p = self.by_hash[hash_restriction]
            if p.body().name() is not None:
                if name != p.body().name():
                    raise ValueError(f'Found packet hash {hash_restriction}, but request name {name} does not match packet {p.body().name()}')
            return p

        def close(self):
            pass

    class PacketMemoryWriter(PacketMemoryReader, PacketWriter):
        """
        An in-memory cache of packets that can be written to.  They are stored as an in-order
        list and a map by content-object hash.

        The PacketMemoryWriter is also a reader to simplify tests.
        """
        def __init__(self):
            super().__init__([])
            self.total_bytes_by_packet = 0
            self.total_bytes_by_hash = 0

        def __len__(self):
            return len(self.by_hash)

        def __eq__(self, other):
            if not isinstance(other, TreeIO.PacketMemoryWriter):
                return False
            return self.packets == other.packets

        def __repr__(self):
            return f"PacketMemoryWriter({self.by_hash})"

        def put(self, packet: Packet):
            self.total_bytes_by_packet += len(packet)
            self.packets.append(packet)
            if packet.content_object_hash() not in self.by_hash:
                self.total_bytes_by_hash += len(packet)
                self.by_hash[packet.content_object_hash()] = packet

    class DirectoryBase(ABC):
        def to_path(self, input: Packet | Name | HashValue, nested: bool = False):
            if isinstance(input, Packet):
                ptr = SizedPointer(content_object_hash=input.content_object_hash(), length=0)
                filename = ptr.file_name()
            elif isinstance(input, HashValue):
                filename = input.value().tobytes().hex()
            elif isinstance(input, Name):
                filename = TreeIO.get_link_name(input)
            else:
                raise TypeError(f'Unsupported input type: {input}')

            if nested:
                subdir1 = filename[0:2]
                subdir2 = filename[2:4]
                dir_path = Path(self._directory, subdir1, subdir2)
                dir_path.mkdir(parents=True, exist_ok=True)
                return PurePath(self._directory, subdir1, subdir2, filename)

            return PurePath(self._directory, filename)

    class PacketDirectoryWriter(PacketWriter, DirectoryBase):
        """
        A file-system based write.  Packets are saved to the directory using their
        hash-based named (in UTF-8 hex).
        """
        def __init__(self, directory: str, link_named_objects: bool = False, signer: Optional[Signer] = None, nested: bool = False):
            """

            :param directory: The directory to use for I/O.  Must exist.
            :param link_named_objects: If true, and the content object has a name, create a link from the name to the hash.
            :param signer: Used to sign link objects.  If not provided, use CRC32c.
            """
            if not os.path.isdir(directory):
                raise RuntimeError("directory does not exist: %r" % directory)

            self._directory = directory
            self._link_named_objects = link_named_objects
            self._signer = signer
            self._nested = nested

            self.by_hash = {}
            self.packets = []
            self.total_bytes_by_packet = 0
            self.total_bytes_by_hash = 0
            self.cnt_manifest = 0
            self.cnt_data = 0
            self.bytes_manifest = 0
            self.bytes_data = 0

        def put(self, packet: Packet):
            self.total_bytes_by_packet += len(packet)
            packet.save(self.to_path(input=packet, nested=self._nested))
            self._write_link(packet)
            if packet.content_object_hash() not in self.by_hash:
                self.total_bytes_by_hash += len(packet)
                self.by_hash[packet.content_object_hash()] = packet
                if packet.body().is_manifest():
                    self.cnt_manifest += 1
                    self.bytes_manifest += len(packet)
                else:
                    self.cnt_data += 1
                    self.bytes_data += len(packet)

        def _create_link(self, packet: Packet) -> Packet:
            link = Link(name=packet.body().name(), digest=packet.content_object_hash())
            link_object = ContentObject.create_link(name=packet.body().name(), link=link)
            return self._create_signed_packet(link_object)

        def _write_link(self, packet: Packet):
            if not self._link_named_objects or not packet.body().is_content_object():
                return
            if packet.body().name() is None:
                return
            link_packet = self._create_link(packet=packet)
            link_packet.save(self.to_path(packet.body().name()))

        def _create_signed_packet(self, link_object: ContentObject) -> Packet:
            if self._signer is None:
                signer = Crc32cSigner()
            else:
                signer = self._signer

            alg = signer.validation_alg()
            signature = signer.sign(link_object.serialize(), alg.serialize())
            return Packet.create_signed_content_object(body=link_object, validation_alg=alg, validation_payload=signature)

        def close(self):
            pass

    class PacketDirectoryReader(PacketReader, DirectoryBase):
        """
        A file-system based packet reader.  Reads packets based on their hash name from a directory
        """

        def __iter__(self):
            # TODO: Open the directory and iterate all the files in it
            raise NotImplementedError()

        def __init__(self, directory):
            """

            :param directory: The directory to use for I/O.  Must exist.
            """
            if not os.path.isdir(directory):
                raise RuntimeError("directory does not exist: %r" % directory)
            self._directory = directory

        def get(self, name: Name, hash_restriction: HashValue, forwarding_hints: Optional[Locators] = None) -> Packet:
            if name is not None and hash_restriction is None:
                return self._get_by_name(name)

            # ccnx does not use forwarding hint
            path = self.to_path(hash_restriction)
            p = Packet.load(path)
            if p.body().name() is not None:
                if name != p.body().name():
                    raise ValueError(f'Found packet hash {hash_restriction}, but request name {name} does not match packet {p.body().name()}')
            return p

        def _get_by_name(self, name: Name) -> Packet:
            """
            Try fetching a link with that name, otherwise search the directory

            :throws FileNotFoundError: If cannot find an object with that name
            """
            try:
                return self._get_by_link(name)
            except FileNotFoundError:
                pass

            # try searching all the content objects
            raise NotImplementedError(f'Could not find {name} by link, search not implemented')

        def _get_by_link(self, name: Name):
            link_path = self.to_path(name)
            p = Packet.load(link_path)
            # TODO: we should validate p, but that needs a keystore
            if p.body().is_link():
                link = Link.deserialize(p.body().payload().value())
                hash_path = self.to_path(link.digest())
                packet = Packet.load(hash_path)
                print(f"Dereferenced link {filename} to load packet {packet.content_object_hash()}")
                return packet
            raise FileNotFoundError(f'Could not find link {filename}')

        def close(self):
            pass

    class PacketNetworkWriter(PacketWriter):
        """
        Packets are written to a ccnxd via a network socket.
        """
        def __init__(self, host="127.0.0.1", port=9896):
            """
            """
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.connect((host, port))

        def close(self):
            if self._socket is not None:
                self._socket.close()
            self._socket = None

        def put(self, packet: Packet):
            self._socket.sendall(packet.serialize().tobytes())
