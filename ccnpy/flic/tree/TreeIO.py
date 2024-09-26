#  Copyright 2019 Marc Mosko
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
import abc
import os
import socket
from array import array
from pathlib import PurePath

import ccnpy
from ccnpy import Packet


class TreeIO:
    """
    A set of utility classes used for in-memory tree input/output

    """

    @staticmethod
    def _create_data_packet(application_data):
        payload = ccnpy.Payload(application_data)
        packet = ccnpy.Packet.create_content_object(ccnpy.ContentObject.create_data(payload=payload))
        return packet

    @classmethod
    def chunk_data_to_packets(cls, application_data, chunk_size):
        """
        For example, if the application_data is [1, 2, 3, 4, 5, 6, 7] and chunk_size is 2, then the return will be
        packets with payloads [1,2], [3, 4], [5, 6], and [7].

        :param application_data: An array (or list) of application data
        :param chunk_size: The number of array elements to put in each packet's payload
        :return:
        """
        packets = []
        count = len(application_data)
        for i in range(0, count, chunk_size):
            data = application_data[i:(i+chunk_size)]
            packet = cls._create_data_packet(data)
            packets.append(packet)

        return packets

    class DataBuffer:
        def __init__(self):
            self.buffer = array("B", [])
            self.count = 0

        def __repr__(self):
            return "{DataBuffer %r, %r}" % (self.count, self.buffer)

        def append(self, data):
            self.count += 1
            self.buffer.extend(data)

    class PacketWriter(abc.ABC):
        @abc.abstractmethod
        def put(self, packet: Packet):
            pass

        def close(self):
            pass

    class PacketMemoryReader:
        """
        An in-memory cache of packets that can be fetch by their content object hash
        """
        def __init__(self, packets):
            self.index = {}
            for packet in packets:
                # print("PacketInput: add key %r" % packet.content_object_hash())
                self.index[packet.content_object_hash()] = packet

        def get(self, hash_value):
            return self.index[hash_value]

    class PacketMemoryWriter(PacketWriter):
        """
        An in-memory cache of packets that can be written to.  They are stored as an in-order
        list and a map by content-object hash.
        """
        def __init__(self):
            self.packets = []
            self.by_hash = {}

        def __len__(self):
            return len(self.by_hash)

        def put(self, packet: Packet):
            self.packets.append(packet)
            self.by_hash[packet.content_object_hash()] = packet

        def get(self, hash_value):
            return self.by_hash[hash_value]

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
            ptr = ccnpy.flic.tree.SizedPointer(content_object_hash=packet.content_object_hash(), length=0)
            path = PurePath(self._directory, ptr.file_name())
            packet.save(path)

        def get(self, hash_value):
            ptr = ccnpy.flic.tree.SizedPointer(content_object_hash=hash_value, length=0)
            path = PurePath(self._directory, ptr.file_name())
            packet = ccnpy.Packet.load(path)
            return packet

    class PacketDirectoryReader:
        """
        A file-system based packet reader.  Reads packets based on their hash name from a directory
        """
        def __init__(self, directory):
            """

            :param directory: The directory to use for I/O.  Must exist.
            """
            if not os.path.isdir(directory):
                raise RuntimeError("directory does not exist: %r" % directory)

            self._directory = directory

        def get(self, hash_value):
            ptr = ccnpy.flic.tree.SizedPointer(content_object_hash=hash_value, length=0)
            path = PurePath(self._directory, ptr.file_name())
            packet = ccnpy.Packet.load(path)
            return packet

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
