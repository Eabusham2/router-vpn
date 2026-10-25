#!/usr/bin/env python3
"""Verify the kernel driver's receipt/ownership rejection before privileged CI."""
from pathlib import Path
import copy
import importlib.util
import unittest

SOURCE = Path(__file__).with_name("test_desktop_node_mtu_kernel.py")
spec = importlib.util.spec_from_file_location("native_node_kernel", SOURCE)
DRIVER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DRIVER)


def record():
    return {"schema": 1, "session_id": "a" * 32, "config_sha256": "b" * 64,
            "path_id": "c" * 64, "generation": 1, "request_id": "d" * 32,
            "lease_id": "e" * 32, "active": True, "restored": False,
            "reader": 1, "interface": DRIVER.INTERFACE, "index": 17, "mtu": 1420,
            "heartbeat_at": 123456789}


class KernelReceiptContract(unittest.TestCase):
    def test_exact_readback_is_accepted(self):
        original = record()
        self.assertEqual(DRIVER.validate_record(copy.deepcopy(original), "a" * 32, "b" * 64), original)

    def test_foreign_or_malformed_native_receipt_is_rejected(self):
        for field, wrong in (("schema", True), ("session_id", "f" * 32), ("config_sha256", "f" * 64),
                             ("path_id", "not-captured"), ("reader", 0), ("index", -1), ("mtu", 9001),
                             ("mtu", True), ("heartbeat_at", 0), ("generation", True), ("request_id", "wrong"),
                             ("lease_id", "wrong"), ("active", 1), ("restored", 0), ("expired", 1),
                             ("revert_token", "f" * 32), ("commit_request", "f" * 32),
                             ("commit_generation", 3), ("interface", "eth0")):
            with self.subTest(field=field, value=wrong):
                changed = record()
                changed[field] = wrong
                with self.assertRaises(AssertionError):
                    DRIVER.validate_record(changed, "a" * 32, "b" * 64)

    def test_stopped_requires_same_owner_and_absent_kernel_interface(self):
        stopped = {"schema": 1, "session_id": "a" * 32, "source_sha256": "b" * 64, "closed": True}
        DRIVER.validate_stopped(stopped, "a" * 32, "b" * 64, False)
        for field, wrong in (("schema", True), ("session_id", "f" * 32), ("source_sha256", "f" * 64),
                             ("closed", False), ("closed", 1)):
            with self.subTest(field=field, value=wrong):
                with self.assertRaises(AssertionError):
                    DRIVER.validate_stopped({**stopped, field: wrong}, "a" * 32, "b" * 64, False)
        with self.assertRaisesRegex(AssertionError, "preceded kernel TUN cleanup"):
            DRIVER.validate_stopped(stopped, "a" * 32, "b" * 64, True)

    def test_rejected_command_cannot_change_any_retained_owner_field(self):
        before = record()
        request = {"generation": 2, "request_id": "f" * 32}
        result = {**before, **request, "failure": "captured TUN operation rejected"}
        DRIVER.validate_command(result, before, request, True)
        for field, wrong in (("reader", 2), ("index", 18), ("mtu", 1360), ("active", False),
                             ("restored", True), ("lease_id", "f" * 32), ("interface", "eth0"),
                             ("path_id", "f" * 64), ("generation", 3), ("request_id", "a" * 32),
                             ("failure", ""), ("expired", True)):
            with self.subTest(field=field):
                with self.assertRaises(AssertionError):
                    DRIVER.validate_command({**result, field: wrong}, before, request, True)

    def test_success_cannot_hide_rejection_or_borrow_another_ack(self):
        before = record()
        request = {"generation": 2, "request_id": "f" * 32}
        result = {**before, **request, "reader": 2, "index": 18, "mtu": 1360}
        DRIVER.validate_command(result, before, request, False)
        for field, wrong in (("failure", "rejected"), ("failure", 0), ("path_id", "f" * 64),
                             ("generation", 3), ("request_id", "a" * 32)):
            with self.subTest(field=field):
                with self.assertRaises(AssertionError):
                    DRIVER.validate_command({**result, field: wrong}, before, request, False)


if __name__ == "__main__":
    unittest.main()
