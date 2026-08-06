# Install or repair through SSH

## 1. Open Terminal on the Mac

Press `Command + Space`, type `Terminal`, and press Return.

## 2. Connect to the AI Board Linux host

```bash
ssh YOUR_AI_BOARD_USERNAME@192.168.50.133
```

Type `yes` and press Return the first time. Enter the AI Board Linux password.

If SSH uses another port:

```bash
ssh -p PORT YOUR_AI_BOARD_USERNAME@192.168.50.133
```

## 3. Clone only the private project repository

```bash
cd /tmp
git clone https://github.com/Eabusham2/router-vpn.git
cd router-vpn
```

GitHub username: `Eabusham2`. Use a fine-grained token as the password.

## 4. Install

```bash
sudo ./server/install.sh
```

Accept the defaults or enter the requested values. Use the AI Board interface shown by:

```bash
ip route show default
```

The interface after `dev` is the value, commonly `eth0`.

## 5. Diagnose

```bash
sudo /opt/router-vpn/source/server/scripts/doctor.sh
```

## 6. Update a changed home public IPv4

Run this while at home, then download the replacement client bundle:

```bash
sudo /opt/router-vpn/source/server/scripts/update-endpoint.sh /opt/router-vpn AUTO
```
