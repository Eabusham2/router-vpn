# Install or repair through SSH

## 1. Open Terminal

On Mac: Command + Space → type `Terminal` → Return.

## 2. SSH to the AI Board Linux host

```bash
ssh YOUR_AI_BOARD_USERNAME@192.168.50.133
```

Type `yes` once, then enter the AI Board Linux password.

For a custom SSH port:

```bash
ssh -p PORT YOUR_AI_BOARD_USERNAME@192.168.50.133
```

## 3. Clone only the private project repo

```bash
cd /tmp
rm -rf router-vpn
git clone https://github.com/Eabusham2/router-vpn.git
cd router-vpn
```

Use `Eabusham2` as the username and a fine-grained read-only token as the password.

## 4. Install

```bash
sudo ./server/install.sh
```

At the endpoint question, leave it blank. Choose the public IPv4, global IPv6, or hostname later inside the client app.

To identify the AI Board interface:

```bash
ip route show default
```

Use the name after `dev`, commonly `eth0`.

## 5. Diagnose

```bash
sudo /opt/router-vpn/source/server/scripts/doctor.sh
```

## 6. Get the bundle

```bash
sudo /opt/router-vpn/source/server/scripts/export-client.sh
```

Or download it on the home LAN:

```text
http://192.168.50.133:8786/router-vpn-client-bundle.zip
```

Changing the home public IP does not require rebuilding the client. Edit the selected router endpoint in the app while disconnected.
