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


import binascii

import jsbeautifier


class DisplayFormatter:
    @classmethod
    def hexlify(cls, value):
        if value is None:
            return "None"
        return f'0x{str(binascii.hexlify(value), 'utf-8')}'

    @classmethod
    def prettify(cls, value):
        """
        Takes the standard __repr__ of objects and makes it pretty

        :param value:
        :return:
        """

        if not isinstance(value, str):
            value = str(value
                        )
        opts = jsbeautifier.default_options()
        opts.end_with_newline = True
        opts.indent_size = 3
        opts.space_in_empty_paren = True
        opts.wrap_line_length = 80

        pretty = jsbeautifier.beautify(value, opts)
        return pretty
