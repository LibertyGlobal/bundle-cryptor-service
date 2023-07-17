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

"""Worker process class, responsible for translating RabbitMQ messages from ABS to BundleGen."""
from multiprocessing import Process
from typing import TYPE_CHECKING
import logging
import os

from pika import (
    BlockingConnection,
    ConnectionParameters,
)
from pika.adapters.blocking_connection import BlockingChannel
from pika.exceptions import (
    AMQPChannelError,
    AMQPConnectionError,
    ConnectionClosedByBroker,
)

from service.config import Config
from service.handlers import BundleCryptHandler
from service.utils import create_dirs_from_envs


if TYPE_CHECKING:  # pragma: no cover
    from service.handlers import Handler


class Worker(Process):
    """Get message from `worker.in_queue`.

    Transfrom to BundleGen format, send to `worker.out_queue`.
    """

    def __init__(self, config: Config, handler: "Handler") -> None:
        """Initialize worker instance with config, formatter and downloader."""
        super().__init__()
        self.config = config
        self.handler = handler
        self.logger = logging.getLogger(self.__class__.__name__)

    def initialize_channel(self) -> BlockingChannel:
        """Initialize connection to RabbitMQ and return communication channel."""
        params = ConnectionParameters(
            host=os.environ.get("RABBITMQ_HOST", "localhost"),
            port=int(os.environ.get("RABBITMQ_PORT", 5672)),
            connection_attempts=int(os.environ.get("RABBITMQ_CONNECTION_ATTEMPTS", 5)),
            retry_delay=int(os.environ.get("RABBITMQ_RETRY_DELAY", 5)),  # type: ignore[arg-type]
        )
        connection = BlockingConnection(parameters=params)

        self.logger.debug("Initialize channel with and params=`%s`", params)

        return connection.channel()

    def queues_declare(self, channel: BlockingChannel) -> None:
        """Create a queue if queue doesn't exist."""
        channel.queue_declare(queue=self.config.get("worker.in_queue"), durable=True)
        channel.queue_declare(queue=self.config.get("worker.status_queue"), durable=True)

    def run(self) -> None:
        """Process all messages from ABS to BundleGen."""
        try:
            self.logger.info("Trying to connect to RabbitMQ...")

            channel = self.initialize_channel()

            self.queues_declare(channel)

            # start consuming from multiple queues
            channel.basic_consume(
                queue=self.config.get("worker.in_queue"),
                on_message_callback=self.handler.h_request,
            )
            self.logger.info("Connected to RabbitMQ broker. Waiting for messages...")

            channel.start_consuming()
        except ConnectionClosedByBroker as exc:
            self.logger.error("Connection was closed by broker: %s", exc)
            self.close()
        except AMQPChannelError as exc:
            self.logger.error("AMPQ Channel error, cannot recover: %s", exc)
            self.close()
        except AMQPConnectionError as exc:
            self.logger.error("Lost connection to rabbitmq: %s", exc)
            self.close()


def main() -> None:
    """Run `concurency` number of Worker."""
    config = Config(os.environ.get("BUNDLE_CONFIG_FILE", "service/config_dev.json"))
    create_dirs_from_envs(config)
    workers = [
        Worker(
            config,
            BundleCryptHandler(config),
        )
        for _ in range(config.get("concurency"))
    ]

    for worker in workers:
        worker.start()

    for worker in workers:
        worker.join()


if __name__ == "__main__":  # pragma: no cover
    main()
