#!/bin/sh
# Turn a fresh Debian/Ubuntu VPS into a relay for the site hosted on a home PC.
#
#   visitor --HTTPS--> Caddy on the VPS --> 127.0.0.1:18080 --SSH reverse tunnel--> PC 127.0.0.1:8080
#
# Caddy gets Let's Encrypt certificates for the domain by itself. The PC connects as the
# user "tunnel", which can only open the one reverse port: no shell, no other forwarding.
# The site's own password (tools/serve_site.py) stays in place; Caddy passes it through.
#
# Run as root:  sh setup_relay.sh <domain> "<tunnel public key line>"
# Example:      sh setup_relay.sh topsecretapi.online "ssh-ed25519 AAAA... codebloodhound-relay"
# Safe to run again: it rewrites only the files it owns.

set -eu

DOMAIN="${1:?domain, e.g. topsecretapi.online}"
KEY="${2:?public key line for the tunnel user}"
PORT=18080

case "$DOMAIN" in *[!A-Za-z0-9.-]*|"") echo "Bad domain: $DOMAIN" >&2; exit 1 ;; esac
case "$KEY" in "ssh-ed25519 "*) ;; *) echo "Expected an ssh-ed25519 public key line" >&2; exit 1 ;; esac
case "$KEY" in *[\"\'\\]*) echo "The key line has unexpected characters" >&2; exit 1 ;; esac
[ "$(printf '%s' "$KEY" | wc -l)" -eq 0 ] || { echo "The key must be one line" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "Run as root" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q ufw openssh-server curl gnupg debian-keyring debian-archive-keyring apt-transport-https
# Caddy from its official repository: distribution packages are missing or too old on some releases
if [ ! -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg ]; then
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key         | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -q
fi
apt-get install -y -q caddy

# Tunnel user: no password, no shell, one reverse port on 127.0.0.1 only
id tunnel >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin tunnel
install -d -m 700 -o tunnel -g tunnel /home/tunnel/.ssh
printf 'restrict,port-forwarding,permitlisten="127.0.0.1:%s",command="/bin/false" %s\n' "$PORT" "$KEY" \
    > /home/tunnel/.ssh/authorized_keys
chown tunnel:tunnel /home/tunnel/.ssh/authorized_keys
chmod 600 /home/tunnel/.ssh/authorized_keys

cat > /etc/ssh/sshd_config.d/60-codebloodhound-tunnel.conf <<EOF
# Written by codebloodhound tools/vps/setup_relay.sh
Match User tunnel
    AllowTcpForwarding remote
    PermitListen 127.0.0.1:$PORT
    GatewayPorts no
    X11Forwarding no
    AllowAgentForwarding no
    PermitTTY no
    PasswordAuthentication no
    ForceCommand /bin/false
    # drop a dead connection quickly so the PC can take the port again after a network change
    ClientAliveInterval 15
    ClientAliveCountMax 3
EOF
sshd -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd

install -d -m 755 -o caddy -g caddy /var/log/caddy
cat > /etc/caddy/Caddyfile <<EOF
# Written by codebloodhound tools/vps/setup_relay.sh
# Both names serve the site, so a stale DNS cache for one of them still leaves the other.
$DOMAIN, www.$DOMAIN {
    encode gzip
    reverse_proxy 127.0.0.1:$PORT {
        transport http {
            response_header_timeout 300s
        }
    }
    handle_errors {
        header Content-Type "text/plain; charset=utf-8"
        respond "CodeBloodhound сейчас недоступен: компьютер с сайтом выключен или переподключается. Попробуйте через минуту." 503
    }
    log {
        output file /var/log/caddy/access.log {
            roll_size 10MiB
            roll_keep 5
        }
    }
}
EOF
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
# validate runs as root and may create the access log; the caddy service must own it
chown -R caddy:caddy /var/log/caddy
systemctl enable caddy >/dev/null 2>&1
systemctl reload caddy 2>/dev/null || systemctl restart caddy

ufw allow 22/tcp >/dev/null
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw --force enable >/dev/null

echo "Relay ready: https://$DOMAIN -> tunnel port 127.0.0.1:$PORT"
echo "DNS A records for $DOMAIN and www.$DOMAIN must point to this server for the certificate."
echo "Visitor addresses are in /var/log/caddy/access.log"
