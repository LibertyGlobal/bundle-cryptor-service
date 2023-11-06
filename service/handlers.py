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

"""Module defines base `Handler` class and all specific childs."""
from enum import Enum
import json
from typing import (
    Any,
    Dict,
    List,
    TYPE_CHECKING,
    Tuple,
)
import logging
import os
from pathlib import Path
import shutil

from pika import BasicProperties
from pika.adapters.blocking_connection import BlockingChannel
from pika.spec import Basic


from bundlecrypt.core import crypt
from service.utils import get_utc_timestamp_ms


if TYPE_CHECKING:  # pragma: no cover
    from service.config import Config

CONFIG_MAP_FILE = "config_map.json"
CONFIG_FILE = "onemw.json"


class Statuses(str, Enum):
    """Ticket's statuses."""

    ENCRYPTION_REQUESTED = "ENCRYPTION_REQUESTED"
    ENCRYPTION_LAUNCHED = "ENCRYPTION_LAUNCHED"
    ENCRYPTION_COMPLETED = "ENCRYPTION_COMPLETED"
    BUNDLE_ERROR = "BUNDLE_ERROR"


class BundleCryptHandler:
    """Handle messages for BundleGen."""

    def __init__(self, config: "Config") -> None:
        self.config = config
        self.configs_path = os.environ.get("BUNDLECRYPT_CONFIG_PATH")
        self.uid = int(os.environ.get("BUNDLECRYPT_UID", 252))
        self.gid = int(os.environ.get("BUNDLECRYPT_GID", 252))
        self.logger = logging.getLogger(self.__class__.__name__)
        self.request_id_map: Dict[str, str] = {}

    def h_request(self, channel: BlockingChannel, method: Basic.Deliver, props: BasicProperties, body: bytes) -> None:
        """Handle input message."""
        self.logger.debug("%s\t%s\t%s", channel, method, props)
        try:
            source_msg = self.make_src_msg(body, props)
            self.logger.info("Received new input message: %s", source_msg)

            src_path, dst_path = self.get_crypt_paths(source_msg["ociBundleUrl"])
            self.send_success_msg(channel, Statuses.ENCRYPTION_LAUNCHED, source_msg["id"])
            self.encrypt_bundle(source_msg["platformName"], src_path, dst_path)
        except Exception as exc:  # pylint: disable=W0703
            self.logger.exception("Exception occurred while formatting message: %s", str(exc))
            source_id = str(props.headers.get("x-request-id", "")) if props.headers is not None else ""
            self.send_error_msg(channel, str(exc), source_id)
        else:
            self.send_success_msg(channel, Statuses.ENCRYPTION_COMPLETED, source_msg["id"])
        finally:
            channel.basic_ack(delivery_tag=method.delivery_tag)  # type: ignore[arg-type]

    def encrypt_bundle(self, platform_name: str,
                       unprotected_bundle_path: str,
                       protected_bundle_path: str) -> None:
        """Encrypt bundle."""
        self.logger.info("Encrypting bundle")
        config_path = os.path.join(self.configs_path, CONFIG_FILE)
        config_id = self.get_config(platform_name)
        self.logger.info(f"{config_path=}, {config_id=}")
        os.makedirs(os.path.dirname(protected_bundle_path), exist_ok=True)
        os.chown(os.path.dirname(protected_bundle_path), uid=self.uid, gid=self.gid)
        crypt(Path(config_path), config_id, unprotected_bundle_path, protected_bundle_path,
              uid=self.uid, gid=self.gid, remove_other_permissions=True)

    def get_config(self, platform_name: str) -> Dict[str, Dict]:
        """Read config map from file"""
        with open(os.path.join(self.configs_path, CONFIG_MAP_FILE)) as f:
            config_map = json.loads(f.read())

        config_map = {k.upper(): v for k, v in config_map.items()}
        return config_map.get(platform_name.upper())

    def debug_output(self, src_path: str, dst_path: str) -> None:
        """Output unencrypted bundle for debugging."""
        new_dst_path, ext = os.path.splitext(dst_path)
        new_dst_path += "_uncrypted%s" % ext
        shutil.copy(src_path, new_dst_path)

    def make_src_msg(self, body: bytes, properties: BasicProperties) -> Dict[str, str]:
        """Prepare message from input queue."""
        src_msg: Dict[str, str] = json.loads(body)
        extended_source_msg: Dict[str, str] = self.extend_message(src_msg, properties.headers)  # type: ignore[arg-type]
        source_id = extended_source_msg.setdefault("id", extended_source_msg["x-request-id"])
        self.request_id_map[source_id] = extended_source_msg["x-request-id"]
        return extended_source_msg

    def get_crypt_paths(self, oci_bundle_path: str) -> Tuple[str, str]:
        """Generate source and destination paths based on oci."""
        bundle_store_path = os.environ.get("BUNDLE_STORE_DIR")
        bundle_nginx_path = os.environ.get("NGINX_STORE_DIR")
        oci_bundle_path = oci_bundle_path.strip("/")
        src_path = os.path.join(bundle_store_path, oci_bundle_path)
        dst_path = os.path.join(bundle_nginx_path, oci_bundle_path)
        return src_path, dst_path

    def extend_message(self, msg: Dict[str, str], headers: Dict[str, str]) -> Dict[str, Any]:
        """Extend message with required fields."""
        result = {}
        c_envs: List[str] = self.config.get("envs")
        c_headers: List[str] = self.config.get("headers")

        for env in c_envs:
            result[env.lower()] = os.environ.get(env)

        for header in c_headers:
            result[header.lower()] = headers.get(header)

        return {**msg, **result}

    def _send_status_message(self, channel: BlockingChannel, msg: Dict[str, Any], uuid: str) -> None:
        """Send status message for ABS."""
        channel.basic_publish(
            exchange="",
            routing_key=self.config.get("worker.status_queue"),
            body=json.dumps(msg),
            properties=BasicProperties(
                delivery_mode=2,  # make message persistent
                headers={"x-request-id": self.request_id_map.get(uuid, uuid), },
            ),
        )

    def send_error_msg(self, channel: BlockingChannel, message: str, uuid: str) -> None:
        """Send error status message for ABS."""
        self._send_status_message(
            channel,
            {
                "id": uuid,
                "phaseCode": Statuses.BUNDLE_ERROR.value,
                "messageTimestamp": get_utc_timestamp_ms(),
                "error": {
                    "code": "BUNDLE_ERROR",
                    "message": message,
                },
            },
            uuid,
        )

    def send_success_msg(self, channel: BlockingChannel, phase_code: Statuses, uuid: str) -> None:
        """Send encryption status message for ABS."""
        self._send_status_message(
            channel,
            {
                "id": uuid,
                "phaseCode": phase_code.value,
                "messageTimestamp": get_utc_timestamp_ms(),
            },
            uuid,
        )
