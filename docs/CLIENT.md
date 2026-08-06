# Use the VPN and SOCKS5 proxy

## macOS

1. Extract `router-vpn-client-bundle.zip`.
2. Open Terminal in the extracted folder.
3. Run:

```bash
chmod +x client/install-macos.sh
./client/install-macos.sh .
```

4. Start the controller with the command printed by the installer.
5. Open `http://127.0.0.1:8788`.
6. Choose **AUTO** or a ready mode.
7. Press **Connect**.
8. At home, press **Off**.

## Linux

From the extracted bundle:

```bash
sudo ./client/install-linux.sh .
```

Open `http://127.0.0.1:8788`.

## Windows

The ZIP contains `dist/router-vpn-client-windows-amd64.exe`, but the all-engine Windows installer is not completed. Raw profiles can be imported into their normal protocol apps; the custom controller is currently complete for macOS/Linux.

## SOCKS5

1. Connect the VPN first.
2. The Router VPN UI displays the SOCKS5 address, port, username, and password.
3. In the app that should use the proxy, choose **SOCKS5** and enter those values.
4. Enable “proxy DNS through SOCKS” when the app offers it.

SOCKS5 is intentionally not exposed directly to the internet.

## Port forwarding to the remote device

Port forwarding works while connected through WireGuard Raw or AmneziaWG 2 because those modes assign the remote device a tunnel IP.

1. Connect WireGuard/AWG.
2. In **Port forwarding**, select `tcp`, `udp`, or `both`.
3. Enter:
   - `From`: first public port
   - `To`: last public port
   - `Target`: destination port; use the same port for a single-port mapping
4. Press **Apply**.
5. For all unreserved ports, press **Protected DMZ**.
6. Press **Clear** to remove dynamic rules.

## AUTO

AUTO tests every installed, generated, ready mode and connects the one with the fastest successful health check. Missing integration modes are skipped automatically.

## Jumbo payloads

Leave Jumbo off normally. Turn it on only for a TUN proxy mode when the client OS supports large TUN/GSO traffic. WireGuard and AWG keep their safe tunnel MTUs automatically.
