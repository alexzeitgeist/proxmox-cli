"""
Task polling utility for Proxmox CLI.
"""

import time
from typing import Optional, Tuple


class TaskPoller:
    """Utility for polling Proxmox task status."""

    def __init__(self, client, default_timeout: int = 60):
        self.client = client
        self.default_timeout = default_timeout

    def wait_for_task(
        self, node: str, upid: str, timeout: Optional[int] = None
    ) -> Tuple[bool, str]:
        """Wait for a task to complete. Returns (success, status_message)."""
        timeout = timeout or self.default_timeout
        start_time = time.monotonic()

        while time.monotonic() - start_time < timeout:
            try:
                status = self.client.retry(
                    lambda: self.client.proxmox.nodes(node).tasks(upid).status.get(),
                    attempts=2,
                    base_delay=0.5,
                )
            except Exception:
                # Treat errors during polling as transient; continue until timeout
                time.sleep(1)
                continue

            if status.get("status") == "stopped":
                if "exitstatus" in status:
                    success = status["exitstatus"] == "OK"
                    return success, status.get("exitstatus", "Unknown")
                return True, "Completed"

            time.sleep(1)

        return False, f"Timeout after {timeout} seconds"

