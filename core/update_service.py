"""Update service: background scheduler, single-flight check, tray integration."""
from __future__ import annotations

import logging
import random
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from .. import __version__
from ..installer.update_check import (
    CheckResult,
    UpdateResult,
    download_installer,
    fetch_manifest,
)
from .user_paths import updates_dir, user_data_dir

log = logging.getLogger(__name__)

MANIFEST_URL = "https://updates.example.com/updates/manifest.json"
CHECK_INTERVAL_SECONDS = 24 * 60 * 60
INITIAL_JITTER_MAX = 180
ERROR_BACKOFF = 60 * 60
ERROR_BACKOFF_MAX = 6 * 60 * 60


class UpdateService:
    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._checking = threading.Lock()
        self._last_check: Optional[datetime] = None
        self._last_result: Optional[CheckResult] = None
        self._on_update_available: Optional[Callable[[CheckResult], None]] = None
        self._on_check_done: Optional[Callable[[CheckResult], None]] = None
        self._consecutive_errors = 0

    @property
    def last_result(self) -> Optional[CheckResult]:
        return self._last_result

    @property
    def last_check(self) -> Optional[datetime]:
        return self._last_check

    def set_callbacks(
        self,
        on_update_available: Optional[Callable[[CheckResult], None]] = None,
        on_check_done: Optional[Callable[[CheckResult], None]] = None,
    ) -> None:
        self._on_update_available = on_update_available
        self._on_check_done = on_check_done

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="update-service")
        self._thread.start()
        log.info("UpdateService started")

    def stop(self) -> None:
        self._stop.set()
        log.info("UpdateService stopping")

    def check_now(self) -> CheckResult:
        if self._checking.locked():
            return CheckResult(UpdateResult.NO_UPDATE, detail="check already in progress")
        with self._checking:
            return self._do_check()

    def prepare_install(self, result: CheckResult) -> Optional[Path]:
        if not result.manifest:
            return None
        dl_result = download_installer(result.manifest, updates_dir())
        if dl_result.result != UpdateResult.UPDATE_AVAILABLE:
            return None
        version = result.manifest["version"]
        installer = updates_dir() / f"GadSignLocalAPI-{version}-setup.exe"
        return installer if installer.exists() else None

    def launch_installer(self, installer: Path) -> bool:
        args = [
            str(installer),
            "/VERYSILENT",
            "/SUPPRESSMSGBOXES",
            "/NORESTART",
        ]
        try:
            subprocess.Popen(args, shell=False)
            log.info("Installer launched: %s", installer)
            return True
        except Exception as exc:
            log.error("Failed to launch installer: %s", exc)
            return False

    def _loop(self) -> None:
        jitter = random.randint(60, INITIAL_JITTER_MAX)
        log.debug("UpdateService: first check in %ss", jitter)
        time.sleep(jitter)

        while not self._stop.is_set():
            with self._checking:
                result = self._do_check()
            wait = self._next_wait(result)
            log.debug("UpdateService: next check in %ss", wait)
            self._stop.wait(wait)

    def _do_check(self) -> CheckResult:
        self._last_check = datetime.now(timezone.utc)
        result = fetch_manifest(MANIFEST_URL, __version__)
        self._last_result = result

        if result.result == UpdateResult.UPDATE_AVAILABLE:
            self._consecutive_errors = 0
            log.info("Update available: %s", result.manifest and result.manifest.get("version"))
            if self._on_update_available:
                try:
                    self._on_update_available(result)
                except Exception as exc:
                    log.error("on_update_available callback error: %s", exc)
        elif result.result == UpdateResult.NO_UPDATE:
            self._consecutive_errors = 0
        else:
            self._consecutive_errors += 1
            log.warning("Update check failed [x%d]: %s", self._consecutive_errors, result.detail)

        if self._on_check_done:
            try:
                self._on_check_done(result)
            except Exception as exc:
                log.error("on_check_done callback error: %s", exc)

        return result

    def _next_wait(self, result: CheckResult) -> int:
        if result.result in {UpdateResult.UPDATE_AVAILABLE, UpdateResult.NO_UPDATE}:
            return CHECK_INTERVAL_SECONDS
        backoff = ERROR_BACKOFF * (2 ** (self._consecutive_errors - 1))
        return min(backoff, ERROR_BACKOFF_MAX)
