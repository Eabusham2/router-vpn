#!/usr/bin/env python3
"""Exercise startup PID identity retries without weakening shutdown ownership."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
SPEC=importlib.util.spec_from_file_location('runtime_pids',Path(__file__).with_name('runtime-pids.py'))
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)
class Registration(unittest.TestCase):
    def run_record(self,starts,commands,zombie=False):
        with tempfile.TemporaryDirectory() as folder:
            M.init(folder,'native')
            with patch.object(M,'process_start',side_effect=starts),patch.object(M,'process_command_hash',side_effect=commands),patch.object(M,'process_is_zombie',return_value=zombie),patch.object(M.time,'sleep') as pause:
                try:M.record(folder,'native','1234')
                except RuntimeError:
                    self.assertEqual(M.read_registry(M.mode_file(folder,'native')),[])
                    raise
                records=M.read_registry(M.mode_file(folder,'native'))
                return records,pause.call_count
    def test_exec_transition_is_bounded_and_keeps_original_identity(self):
        records,pauses=self.run_record(['linux:100']*3,['','a'*64])
        self.assertEqual(records,[{'version':1,'pid':1234,'start':'linux:100','command_sha256':'a'*64}])
        self.assertEqual(pauses,1)
    def test_empty_cmdline_never_becomes_an_ownership_record(self):
        with self.assertRaisesRegex(RuntimeError,'cannot identify'):self.run_record(['linux:100']*5,['']*4)
    def test_pid_reuse_during_registration_is_rejected(self):
        for commands in [['a'*64],['']]:
            with self.assertRaisesRegex(RuntimeError,'changed identity'):self.run_record(['linux:100','linux:200'],commands)
    def test_exited_child_is_not_waited_into_a_different_process(self):
        with self.assertRaisesRegex(RuntimeError,'exited before'):self.run_record(['linux:100']*2,[''],True)
    def test_ready_child_requires_no_delay(self):
        records,pauses=self.run_record(['linux:100']*2,['b'*64])
        self.assertEqual(pauses,0);self.assertEqual(records[0]['command_sha256'],'b'*64)
if __name__=='__main__':unittest.main()
