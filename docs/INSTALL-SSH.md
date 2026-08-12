# Install or repair Router VPN through SSH

Portainer is the normal ASUS AI Board deployment path. This terminal path is for Docker hosts where SSH access is actually available.

```bash
git clone https://github.com/Eabusham2/router-vpn.git
cd router-vpn
sudo ./server/install.sh
```

The repository is public; a Git token is not normally required.

`server/install.sh` uses the same **image-only** `server/portainer-current.yaml` as Portainer. It does not turn the server host into the normal image build environment.

Update later with:

```bash
sudo ./server/upgrade.sh
```

or:

```bash
sudo ./server/manage.sh
```

Diagnostics:

```bash
sudo bash server/scripts/doctor-current.sh
```

Setup Center:

```text
http://AI_BOARD_IP:8786/
```

Client downloads remain GitHub-artifact-first; if the matching client artifact is unavailable, the Setup Center can compile only that requested client package locally and deletes the temporary build afterward.

Do not WAN-forward `8786`.
