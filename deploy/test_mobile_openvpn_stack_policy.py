"""Protect exact source ownership of the native OpenVPN shutdown-order repair."""
from pathlib import Path
import importlib.util
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('openvpn_stack_policy', ROOT/'deploy/mobile_openvpn_stack_policy.py')
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


class Tests(unittest.TestCase):
    def test_exact_pin_idempotency_and_drift(self):
        self.assertEqual(POLICY.SOURCE_SHA, '9a0bd5edd56c4ef64f8d8ae335e2a6dfe4d921dc')
        original = 'func Close() {\n'+POLICY.OLD+'\n}\n'
        with mock.patch.object(POLICY, 'SOURCE_SHA', POLICY.blobsha(original.encode())):
            fixed = POLICY.patch(original)
            self.assertEqual(POLICY.patch(fixed), fixed)
            for changed in (original+'drift', fixed+'drift', fixed+POLICY.NEW,
                            fixed.replace('d.endpoint.Attach(nil)', 'd.endpoint.Attach(other)')):
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    POLICY.patch(changed)
        with self.assertRaises(ValueError):
            POLICY.patch(original)

    def test_linked_fixture_rejected_before_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root/'transport/openvpn/device_stack.go'; source.parent.mkdir(parents=True)
            source.write_text('untouched source')
            unrelated = root/'unrelated'; unrelated.write_text('untouched unrelated')
            source.with_name('routervpn_stack_close_test.go').symlink_to(unrelated)
            with mock.patch.object(POLICY.subprocess, 'check_output', return_value=POLICY.PIN+'\n'):
                with self.assertRaises(ValueError):
                    POLICY.prepare(root)
            self.assertEqual(source.read_text(), 'untouched source')
            self.assertEqual(unrelated.read_text(), 'untouched unrelated')


if __name__ == '__main__':
    unittest.main()
