"""Test-only CryptoKit SHA256 boundary backed by Go's actual crypto/sha256.

Shipping Apple targets use platform CryptoKit. Linux source tests link this
small module without changing the production source or adding a digest hook.
"""
import os
from pathlib import Path
import subprocess
import sys

GO_SOURCE = r'''package main
import("crypto/sha256";"io";"os")
func main(){b,e:=io.ReadAll(io.LimitReader(os.Stdin,(4<<20)+1));if e!=nil||len(b)>4<<20{os.Exit(2)};s:=sha256.Sum256(b);clear(b);if _,e=os.Stdout.Write(s[:]);e!=nil{os.Exit(3)}}
'''
SWIFT_SOURCE = r'''import Foundation
public enum SHA256 {
 public static func hash(data: Data) -> [UInt8] {
  guard data.count <= 4 * 1024 * 1024, let helper = ProcessInfo.processInfo.environment["ROUTERVPN_TEST_SHA256_HELPER"] else {fatalError("Missing bounded test SHA256 provider")}
  let p=Process(),input=Pipe(),output=Pipe();p.executableURL=URL(fileURLWithPath:helper);p.standardInput=input;p.standardOutput=output;p.standardError=FileHandle.nullDevice
  do {try p.run();try input.fileHandleForWriting.write(contentsOf:data);try input.fileHandleForWriting.close()} catch {fatalError("Test SHA256 provider failed")}
  let result=output.fileHandleForReading.readDataToEndOfFile();p.waitUntilExit()
  guard p.terminationStatus==0,result.count==32 else {fatalError("Invalid SHA256 provider result")};return [UInt8](result)
 }
}
'''

def prepare(directory: Path):
    if sys.platform == 'darwin':
        return [], {}
    directory.mkdir(parents=True, exist_ok=True)
    source=directory/'sha256.go';source.write_text(GO_SOURCE)
    helper=directory/'sha256';subprocess.run(['go','build','-o',str(helper),str(source)],check=True,timeout=90)
    swift=directory/'CryptoKit.swift';swift.write_text(SWIFT_SOURCE)
    subprocess.run(['swiftc','-swift-version','6','-emit-library','-emit-module','-module-name','CryptoKit','-emit-module-path',str(directory/'CryptoKit.swiftmodule'),str(swift),'-o',str(directory/'libCryptoKit.so')],check=True,timeout=90)
    return ['-I',str(directory),'-L',str(directory),'-lCryptoKit','-Xlinker','-rpath','-Xlinker',str(directory)], {'ROUTERVPN_TEST_SHA256_HELPER':str(helper)}
