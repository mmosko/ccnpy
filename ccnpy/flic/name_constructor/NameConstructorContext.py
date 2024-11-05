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

from .SchemaImpl import SchemaImpl


class NameConstructorContext:
    """
    This is the top-level name constructor object that is used by `ManifestTree` and related classes.  it defines the
    name constructors used in the manifest and provides the needed behavior to generate names and chunk numbers.
    """

    def __init__(self, manifest_schema: SchemaImpl, data_schema: SchemaImpl):
        """
        The name constructor implementations for the manifest tree and the data tree.  They may be the same
        instance, e.g. for HashedSchema or PrefixSchema.  Or they may be different, such as for the
        SegmentedSchema.

        They must both be defined, even if using the default NcId 0 HashedSchema.
        """

        def get_next_manifest_name(self):
            """
            Get the CCNx name for the next manifest.
            """
            pass



