#!/usr/bin/env python3
import json
import unittest
import test_desktop_mtu_client_context as gate

class DesktopMTUClientContextVerdicts(unittest.TestCase):
    def rows(self):
        return [{'Action':'pass','Package':package,**({'Test':test} if test else {})}
                for package, tests in gate.EXPECTED.items() for test in ['',*tests]]
    def check(self,rows):
        gate.check('\n'.join(json.dumps(row) for row in rows))
    def test_complete(self): self.check(self.rows())
    def test_native_inventory(self):
        rows=[{'Action':'pass','Package':package,**({'Test':test} if test else {})} for package,tests in gate.NATIVE_EXPECTED.items() for test in ['',*tests]]
        gate.check('\n'.join(json.dumps(row) for row in rows),gate.NATIVE_EXPECTED)
        for index in range(len(rows)):
            with self.assertRaises(ValueError):gate.check('\n'.join(json.dumps(row) for row in rows[:index]+rows[index+1:]),gate.NATIVE_EXPECTED)
    def test_every_required_verdict(self):
        rows=self.rows()
        for index in range(len(rows)):
            with self.subTest(index=index):
                with self.assertRaises(ValueError): self.check(rows[:index]+rows[index+1:])
                with self.assertRaises(ValueError): self.check(rows+[rows[index]])
    def test_failure_skip_and_foreign(self):
        for action in ('fail','skip'):
            with self.assertRaises(ValueError): self.check(self.rows()+[{'Action':action,'Package':gate.CLIENT,'Test':'foreign'}])
        rows=self.rows();rows[0]['Package']='foreign'
        with self.assertRaises(ValueError): self.check(rows)

if __name__=='__main__':unittest.main()
