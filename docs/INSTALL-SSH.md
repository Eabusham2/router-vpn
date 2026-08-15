# Install or repair Router VPN through SSH

Portainer is the normal ASUS AI Board deployment path. This terminal path is for Docker hosts where SSH access is actually available.

The tracked `server/portainer-current.yaml` is only a reproducible image-only **template/baseline**. Terminal install/upgrade deliberately rejects it as a current release. First obtain and verify the generated `RouterVPN-Portainer-<release-sha>.yaml` from the **Exact-SHA production compose** workflow for the exact release SHA, following `docs/PRODUCTION-RELEASE.md`.

Then:

```bash
git clone https://github.com/Eabusham2/router-vpn.git
cd router-vpn
export ROUTER_VPN_PRODUCTION_COMPOSE=/absolute/path/RouterVPN-Portainer-<release-sha>.yaml
sudo -E ./server/install.sh
```

The repository is public; a Git token is not normally required. `server/install.sh` verifies the generated release header, exact custom-image pins, matching broker provenance and image-only contract before Docker runs.

Update later with the newly verified generated compose for the target release:

```bash
export ROUTER_VPN_PRODUCTION_COMPOSE=/absolute/path/RouterVPN-Portainer-<release-sha>.yaml
sudo -E ./server/upgrade.sh
```

or:

```bash
export ROUTER_VPN_PRODUCTION_COMPOSE=/absolute/path/RouterVPN-Portainer-<release-sha>.yaml
sudo -E ./server/manage.sh
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
