#!/usr/bin/env python3
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "app" / "src" / "main" / "java" / "com" / "eabusham" / "routervpn" / "AndroidNumericAddress.java"
text = SOURCE.read_text(encoding="utf-8")
for forbidden in ("InetAddress.getByName", "InetAddresses", "Network.getByName"):
    assert forbidden not in text, f"numeric-address parser must remain resolver-free: {forbidden}"
for marker in ("InetAddress.getByAddress(raw)", "parseIPv4", "parseIPv6", "embedded IPv4 IPv6 literals are not accepted", "host.indexOf('%')>=0"):
    assert marker in text, f"numeric-address parser lost marker: {marker}"

javac = shutil.which("javac")
java = shutil.which("java")
assert javac and java, "JDK is required for the Android numeric-address contract"

harness = r'''package com.eabusham.routervpn;
import java.net.InetAddress;
public final class AndroidNumericAddressHarness {
  private static void ok(String text, String expected) throws Exception {
    InetAddress value=AndroidNumericAddress.parse(text);
    if(!value.getHostAddress().equals(expected) && !value.getHostAddress().replace("0:0:0:0:0:0:0:1","::1").equals(expected))
      throw new RuntimeException("parse mismatch for "+text+": "+value.getHostAddress()+" != "+expected);
  }
  private static void bad(String text) throws Exception {
    try { AndroidNumericAddress.parse(text); throw new RuntimeException("accepted invalid literal: "+text); }
    catch(IllegalArgumentException expected) { }
  }
  public static void main(String[] args) throws Exception {
    ok("192.168.50.133","192.168.50.133");
    ok("10.77.0.1","10.77.0.1");
    ok("::1","::1");
    ok("[fd77:77::1]","fd77:77:0:0:0:0:0:1");
    ok("2001:db8::1","2001:db8:0:0:0:0:0:1");
    bad(""); bad("router.local"); bad("001.2.3.4"); bad("256.1.1.1");
    bad("fd77:77::1%wlan0"); bad("2001::db8::1"); bad("2001:db8:1:2:3:4:5:6:7");
    bad("::ffff:192.0.2.1");
  }
}
'''

with tempfile.TemporaryDirectory(prefix="routervpn-numeric-address-") as tmp:
    base = Path(tmp)
    package = base / "com" / "eabusham" / "routervpn"
    package.mkdir(parents=True)
    shutil.copy2(SOURCE, package / SOURCE.name)
    (package / "AndroidNumericAddressHarness.java").write_text(harness, encoding="utf-8")
    out = base / "classes"
    out.mkdir()
    subprocess.run([javac, "-d", str(out), str(package / SOURCE.name), str(package / "AndroidNumericAddressHarness.java")], check=True)
    subprocess.run([java, "-cp", str(out), "com.eabusham.routervpn.AndroidNumericAddressHarness"], check=True)

print("Android numeric address contract: PASS")
