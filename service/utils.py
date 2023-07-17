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

"""Module with utility functions."""
from datetime import datetime
from typing import TYPE_CHECKING
import os


if TYPE_CHECKING:  # pragma: no cover
    from service.config import Config


def get_utc_timestamp_ms() -> int:
    """Return UTC timestamp in milliseconds."""
    return int(datetime.utcnow().timestamp() * 1000)


def create_dirs_from_envs(config: "Config") -> None:
    """Create any directories we need to work if they don't exist."""
    for env_var_name in config.get("envs"):
        dir_path = os.environ.get(env_var_name)

        if not dir_path:
            raise ValueError(f"{env_var_name} is not set")

        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
