#!/usr/bin/env python3
"""Bounded actual-source CONNECT final-layer family; ordinary inventory is separate."""
import sys
import test_android_connect_execution_capture as CAPTURE

compiler_source = CAPTURE.compiler_source
prepare_sources = CAPTURE.prepare_sources

def run(root,work,app,classes,jar,env,imported_only=False):
    CAPTURE.run(root,work,app,classes,jar,env,imported_only=imported_only,family="final-layers")

if __name__=="__main__":
    import test_android_connection_profiles as profiles
    if len(sys.argv)!=1:raise ValueError("This gate takes no arguments")
    sys.argv += ["--case-family","ordered-connect-final-layers"]
    profiles.main()
