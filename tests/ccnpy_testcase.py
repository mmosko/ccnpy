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
import logging.config
import pathlib
import sys
import unittest


class CcnpyTestCase(unittest.TestCase):
    @staticmethod
    def _get_tests_dir():
        p = pathlib.Path().cwd()
        while p.name != 'tests':
            p = p.parent
        return p

    @classmethod
    def setUpClass(cls):
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)

        # this class is way too verbose unless you really want it
        logging.getLogger('ccnpy.flic.tree.Traversal').setLevel(logging.INFO)