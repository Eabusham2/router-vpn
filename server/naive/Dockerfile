FROM pocat/naiveproxy:v150.0.7871.63-1

COPY --chmod=0755 server/naive/entrypoint.sh /usr/local/bin/router-vpn-naive
RUN mkdir -p /srv \
 && printf '%s\n' '<!doctype html><html><head><title>Welcome</title></head><body><h1>Welcome</h1><p>This site is online.</p></body></html>' >/srv/index.html

ENTRYPOINT ["/usr/local/bin/router-vpn-naive"]
