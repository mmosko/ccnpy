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

import ccnpy.flic


class ManifestFactory:
    """
    Streamlines building a Manifest from a source.  The source may be any of ccnpy.flic.Pointers or
    ccnpy.flic.HashGroup or ccnpy.flic.Node.  The factor can also apply a ManifestEncryptor and generate
    encrypted manifests.
    """
    def __init__(self, encryptor=None):
        if encryptor is not None and not issubclass(encryptor.__class__, ccnpy.flic.ManifestEncryptor):
            raise TypeError("Encryptor, if present, must be subclass of ccnpy.flic.ManifestEncryptor")

        self._encryptor = encryptor

    def build(self, source):
        """
        depending on the level of control you wish to have over the manifest creation, you can
        pass one of several types as the source.

        :param source: One of ccnpy.flic.Pointers or ccnpy.flic.HashGroup or ccnpy.flic.Node
        :return: A Manifest
        """
        manifest = None
        if isinstance(source, ccnpy.flic.Pointers):
            manifest = self._build_from_pointers(source)
        elif isinstance(source, ccnpy.flic.HashGroup):
            manifest = self._build_from_pointers(source)
        elif isinstance(source, ccnpy.flic.Node):
            manifest = self._build_from_node(source)
        else:
            raise TypeError("Unsupported type for source: %r" % source)

        return manifest

    def _build_from_pointers(self, pointers):
        """
        From a ccnpy.flic.Pointers object or a list of hash values, build a Manifest.  If the encryptor is
        not None, it will be an encrypted Manifest.
        """
        hg = ccnpy.flic.HashGroup(pointers=pointers)
        return self._build_from_hashgroup(hg)

    def _build_from_hashgroup(self, hg):
        node = ccnpy.flic.Node(hash_groups=[hg])
        return self._build_from_node(node)

    def _build_from_node(self, node):
        if self._encryptor is None:
            manifest = ccnpy.flic.Manifest(node=node)
        else:
            manifest = self._encrypt(node)

        return manifest

    def _encrypt(self, node):
        assert self._encryptor is not None
        security_ctx, encrypted_node, auth_tag = self._encryptor.encrypt(node=node)
        manifest = ccnpy.flic.Manifest(security_ctx=security_ctx, node=encrypted_node, auth_tag=auth_tag)
        return manifest