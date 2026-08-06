# Install from a Linux/AI Board shell

Use this only when you can SSH into the Linux Docker host. ASUSWRT router SSH and the AI Board Linux environment may be separate; Portainer installation is safer on the GT-BE19000AI.

## 1. On your Mac

1. Download and unzip `router-vpn.zip`.
2. Open **Terminal**: Applications → Utilities → Terminal.
3. Go to Downloads:

```bash
cd ~/Downloads
```

4. Copy the folder to the Linux host:

```bash
scp -r router-vpn YOUR_LINUX_USERNAME@192.168.50.133:/tmp/
```

5. Type `yes` once if asked.
6. Enter the Linux password. The password does not appear while typing.
7. Connect:

```bash
ssh YOUR_LINUX_USERNAME@192.168.50.133
```

## 2. Run the installer

```bash
cd /tmp/router-vpn
sudo ./server/install.sh
```

Enter the requested values. Recommended defaults:

```text
AI Board interface: eth0
Home LAN: 192.168.50.0/24
AdGuard: 192.168.50.133
Endpoint: your home public IPv4
WireGuard: 51820
AmneziaWG: 585
REALITY: 443
Hysteria2: 8443
Shadowsocks: 8388
REALITY target: www.microsoft.com:443
```

The installer generates keys, starts containers, enables IPv4/IPv6 forwarding, applies the firewall guard, and creates:

```text
/opt/router-vpn/downloads/router-vpn-client-bundle.zip
```

## 3. Copy the bundle back to the Mac

Exit SSH:

```bash
exit
```

Then:

```bash
scp YOUR_LINUX_USERNAME@192.168.50.133:/opt/router-vpn/downloads/router-vpn-client-bundle.zip ~/Downloads/
```

Complete the ASUS port-forward steps in `INSTALL-PORTAINER.md`.
