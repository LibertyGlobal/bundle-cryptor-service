"""Gets information about the service."""

from datetime import datetime
from typing import Dict
import os
import socket


class Info:
    """Get information about the service."""

    def __init__(self) -> None:
        """Read info."""
        self.app_start_time = datetime.utcnow()
        self.host_name = socket.gethostname()
        self.app_branch = os.getenv("APP_BRANCH", "not specified")
        self.app_name = os.getenv("APP_NAME", "not specified")
        self.app_build_time = os.getenv("APP_BUILD_TIME", "not specified")
        self.app_version = os.getenv("APP_VERSION", "not specified")
        self.stack_name = os.getenv("STACK_NAME", "not specified")
        self.app_revision = os.getenv("APP_REVISION", "not specified")

    def get(self) -> Dict[str, str]:
        """Return info."""
        info: Dict[str, str] = {}
        info['APP_START_TIME'] = self.app_start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        info['HOST_NAME'] = self.host_name
        info['APP_BRANCH'] = self.app_branch
        info['APP_NAME'] = self.app_name
        info['APP_BUILD_TIME'] = self.app_build_time
        info['APP_VERSION'] = self.app_version
        info['STACK_NAME'] = self.stack_name
        info['APP_REVISION'] = self.app_revision
        return info
