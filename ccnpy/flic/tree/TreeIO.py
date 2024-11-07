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
from array import array
from pathlib import PurePath

from .SizedPointer import SizedPointer
from ...core.ContentObject import ContentObject
from ...core.Packet import Packet, PacketWriter, PacketReader
from ...core.Payload import Payload


class TreeIO:
    """
    A set of utility classes used for in-memory tree input/output

    """

    class DataBuffer:
        def __init__(self):
            self.buffer = array("B", [])
            self.count = 0

        def __repr__(self):
            return "{DataBuffer %r, %r}" % (self.count, self.buffer)

        def append(self, data):
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
                self.by_hash = packets.by_hash
            else:
                self.packets = packets
                self.by_hash = {}
                for packet in self.packets:
                    # print("PacketInput: add key %r" % packet.content_object_hash())
                    self.by_hash[packet.content_object_hash()] = packet

        def get(self, hash_value) -> Packet:
            return self.by_hash[hash_value]

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

        def __len__(self):
            return len(self.by_hash)

        def __eq__(self, other):
            if not isinstance(other, TreeIO.PacketMemoryWriter):
                return False
            return self.packets == other.packets

        def __repr__(self):
            return f"PacketMemoryWriter({self.by_hash})"

        def put(self, packet: Packet):
            self.packets.append(packet)
            self.by_hash[packet.content_object_hash()] = packet

    class PacketDirectoryWriter(PacketWriter):
        """
        A file-system based write.  Packets are saved to the directory using their
        hash-based named (in UTF-8 hex).
        """
        def __init__(self, directory):
            """

            :param directory: The directory to use for I/O.  Must exist.
            """
            if not os.path.isdir(directory):
                raise RuntimeError("directory does not exist: %r" % directory)

            self._directory = directory

        def put(self, packet: Packet):
            ptr = SizedPointer(content_object_hash=packet.content_object_hash(), length=0)
            path = PurePath(self._directory, ptr.file_name())
            packet.save(path)

        def close(self):
            pass

    class PacketDirectoryReader(PacketReader):
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

        def get(self, hash_value) -> Packet:
            ptr = SizedPointer(content_object_hash=hash_value, length=0)
            path = PurePath(self._directory, ptr.file_name())
            packet = Packet.load(path)
            return packet

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
