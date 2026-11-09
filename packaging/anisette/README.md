# Anisette server, loopback only

`icp` needs "anisette" data (machine identifiers Apple's sign-in expects). Until it can be produced
natively (see IMPROVEMENTS.md, "Anisette without Docker"), run a local server.

**Never publish it on `0.0.0.0`.** The server has no authentication; with
`-p 6969:6969` Docker binds every interface, so anyone on your Wi-Fi/LAN can ask it for machine
identity data tied to your sign-in (and Docker's firewall rules bypass `ufw`).

Run it bound to loopback:

    docker run -d --restart=always --name icp-anisette \
        -p 127.0.0.1:6969:6969 -v icp-anisette-data:/home/Chester/.config/anisette-v3/lib/ \
        docker.io/dadoum/anisette-v3-server:latest

If you already have a container on `0.0.0.0` (check with `docker ps`), it has no volume, so
removing it loses its provisioned identity: copy it out first
(`docker cp <name>:/home/Chester/.config/anisette-v3 ./anisette-backup`) and copy it back after the new
container has started once.

(`podman` works the same, rootless and without sudo. The volume path is the one the image's own README uses; unverified here. A new container without the old volume gets a new anisette identity, which may cost one extra 2FA prompt.) To fix an existing exposed container:

    docker rm -f <old-container-name>      # then run the command above

Check: `icp doctor` fails/warns if the port answers on a non-loopback address.
Unit files in this directory: `icp-anisette.container` (Podman Quadlet) and
`icp-anisette.service` (plain systemd user unit for Docker or Podman).

Using another host or port: `icp --anisette URL ...`, `ICP_ANISETTE_URL`, or in
`~/.config/icp/config.toml`:

    anisette_url = "http://127.0.0.1:6969"
