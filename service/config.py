#
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2023 Liberty Global Technology Services BV
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""JSON Config module."""
from functools import lru_cache
from typing import (
    Any,
    Dict,
)
import json
import logging


class Config:
    """Load config parameters from JSON file."""

    def __init__(self, path: str = "config_dev.json", sep: str = ".") -> None:
        """Lazy initialization of Config."""
        self._config: Dict[str, Any] = {}
        self.path = path
        self.sep = sep
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.debug("Config created with `%s`", path)

    @property
    def config(self) -> Dict[str, Any]:
        """Load config file."""
        if not self._config:
            with open(self.path, "r", encoding="utf8") as in_file:
                self._config = json.load(in_file)

        return self._config

    @lru_cache
    def get(self, key: str) -> Any:
        """Get value from config file by key/path. Throw exception if there is no key/path."""
        self.logger.debug("Trying to get `%s` in `%s`", key, self.config)
        if self.sep in key:
            paths = key.split(self.sep)
            result = self.config[paths.pop(0)]

            for path in paths:
                result = result[path]
        else:
            result = self.config[key]

        self.logger.debug("Got `%s` = `%s`", key, result)
        return result
