# Remote access: VPN with company sign-in on every connection

LexCorp is never published on the internet. People on the company network reach it directly.
People outside connect through this VPN, and **every connection requires signing in with the
company's existing login**. For this demonstration, the company login is played by
**Sign in with Google**, restricted to an allowlist of accounts.

```
            (1) first time: company portal -> download lexcorp-remote.ovpn (demo stand-in: company-portal-demo/)

 remote laptop                      GATEWAY: public server (free Oracle Cloud VM)        SITE: machine running LexCorp
 OpenVPN GUI --UDP 1194----------> openvpn 172.29.0.2 ==site link (WireGuard, 51820)==> sitelink 172.30.0.2 --HTTPS only--> caddy 172.30.0.10 --> LexCorp
     |                                   |                   opened FROM the site, so it works behind carrier-grade NAT
     | (2) every connection: browser     | "who is this?"
     v                                   v
 https://VPN_HOST:9443 --TCP------> caddy --> auth --> Google: signed in? verified email on ALLOWED_EMAILS? yes -> connected, no -> refused
 (3) connected: open https://APP_HOST  (DuckDNS points it to 172.30.0.10, reachable only through the VPN)
```

The **gateway** is the public front door: the VPN server, the Google sign-in service, the sign-in
page and the DuckDNS updater. The **site** is where LexCorp runs; it keeps an encrypted
WireGuard link open to the gateway and forwards VPN users' HTTPS requests to the app. The site
needs no open ports, so it can sit behind a home or campus connection with carrier-grade NAT
(as the development machine does). In a company, the gateway is the VPN appliance at the network
edge and the site is the internal network.

- **OpenVPN Community Edition** (free, no connection limit) with **openvpn-auth-oauth2**
  (open source, MIT), which asks the identity provider at every connection. In a company,
  Google is replaced by the company's own provider (Microsoft Entra ID, AD FS, Keycloak...),
  the same OIDC standard with a different issuer, client ID and secret.
- **Allowlist:** a connection is accepted only for a Google account whose email is verified
  and listed in `ALLOWED_EMAILS`. Anyone else is refused before reaching the network.
- **A client that can't do the browser sign-in is refused**, even with the profile. The profile's
  certificate is required too, but it identifies the device, not the person.
- **Split tunnel, least privilege:** a connected person gets one route, to the LexCorp proxy
  (HTTPS only). The VPN server, the sign-in service, this machine and the rest of the network
  are unreachable through the VPN. Their own internet traffic doesn't go through it.
- **Real HTTPS for the app:** passkeys and the browser's cryptography only work on HTTPS.
  Caddy gets free Let's Encrypt certificates through DuckDNS (DNS challenge), so the app's
  VPN-only name has a valid certificate without being reachable from the internet.
- **A new address for every connection:** everyone downloads the same profile, and several
  devices can be connected at once (`duplicate-cn`); a small hook (`vpn-client-connect.sh`) gives
  each connection the next free 10.8.0.x, so devices never share an address and a reconnect gets
  a new one. LexCorp binds sessions to the address, so reconnecting the VPN ends the LexCorp
  session ("Your VPN connection was renewed"); that's recorded as an expected event, not an alert.
- **Audit trail:** LexCorp sees each remote person's own VPN address (10.8.0.x). It isn't
  translated away, so the audit trail and the risk model's "new network address" check work.
- **Cost: none.** OpenVPN, openvpn-auth-oauth2, Caddy, DuckDNS, Let's Encrypt, a Google OAuth
  client (testing mode, up to 100 listed users) and the OpenVPN GUI client are all free.

Only the gateway has open ports: UDP 1194 (VPN), TCP 9443 (sign-in page), UDP 51820 (site link).
The site and the app are never exposed.

## Setup (once)

### 1. DuckDNS: two names and a token

1. Sign in at <https://www.duckdns.org> (you can use your Google account).
2. Add two domains, for example `lexcorp-vpn` and `lexcorp-app`. Names are first come,
   first served, so pick others if these are taken.
3. Copy the **token** shown at the top of the page.

The `duckdns` service keeps them up to date by itself: the VPN name follows this network's
public IP (which changes), and the app name points to the proxy's private address `172.30.0.10`.

### 2. Google sign-in client

1. Open <https://console.cloud.google.com>, create a project (for example "LexCorp VPN").
2. **APIs & Services → OAuth consent screen:** choose **External**, app name "LexCorp VPN
   (demo)", your email as support and developer contact. Leave it in **Testing** mode.
   Under **Test users**, add every account that should be able to connect. In testing mode
   Google only lets these accounts sign in at all: a second lock on top of `ALLOWED_EMAILS`.
3. **APIs & Services → Credentials → Create credentials → OAuth client ID**, type **Web
   application**, name "LexCorp VPN sign-in".
   - **Authorised redirect URIs:** `https://<VPN_HOST>:<LOGIN_PORT>/oauth2/callback`,
     for example `https://lexcorp-vpn.duckdns.org:9443/oauth2/callback`.
   - If you will also use the demo company portal (`company-portal-demo/`), add its address
     under **Authorised JavaScript origins**, for example `https://lexcorp-portal.vercel.app`.
4. Copy the **Client ID** and **Client secret**.

### 3. A public server for the gateway (free)

Any Linux server with a public IPv4 address works. The development setup uses an Oracle Cloud
"Always Free" VM (VM.Standard.E2.1.Micro, Ubuntu, 1 GB memory is enough):

1. Create the instance with a public IPv4 address and download its SSH key.
2. In its VCN's security list, add ingress rules from `0.0.0.0/0`: UDP 1194, TCP 9443, UDP 51820.
3. On the server: add swap (`fallocate -l 2G /swapfile`...), install `docker.io` and
   `docker-compose-v2`, load WireGuard (`modprobe wireguard`, plus `/etc/modules-load.d/wireguard.conf`),
   and on Oracle's Ubuntu images open the same three ports in iptables before the final REJECT rule
   (`iptables -I INPUT 5 -p udp --dport 1194 -m state --state NEW -j ACCEPT`, etc., then
   `netfilter-persistent save`).

### 4. Settings and keys

Put the DuckDNS names and token, the Google client ID and secret, and `ALLOWED_EMAILS` in
`network/vpn/.env` (git-ignored; the keys are the same as in `gateway.env.example`), then run:

```
python scripts/vpn_site_link_keys.py
```

It creates `network/vpn/gateway.env` and `network/vpn/site.env` (both git-ignored) with fresh
site-link keys. Copy `gateway.env` to the gateway; `site.env` stays on the site.

### 5. Tell LexCorp its VPN address

In `backend/.env` add:

```
REMOTE_APP_ORIGIN=https://lexcorp-app.duckdns.org
```

(your `APP_HOST`), then restart `npm start`. This adds the name to the allowed origins, lets
Vite answer for it, and makes passkeys created there belong to that name.

### 6. Start it

**Gateway** (on the server, in a folder with `gateway.compose.yml`, `gateway.env`, `openvpn/` and `caddy/`):

```
docker compose -f gateway.compose.yml --env-file gateway.env up -d --build
```

On first start it creates the certificate authority, keys and the client profile
`data/openvpn/client/lexcorp-remote.ovpn`. On a 1 GB server, build the images on another
machine and copy them (`docker save lexcorp-vpn:local lexcorp-vpn-caddy:local | gzip | ssh ... "gunzip | docker load"`),
then start with `--no-build`.

**Site** (on the machine running LexCorp, from `network/vpn`):

```
docker compose -f site.compose.yml --env-file site.env up -d --build
docker compose -f site.compose.yml --env-file site.env logs -f sitelink
```

The site link reports if it can't reach the gateway. Caddy may take a minute to get the
app's certificate.

## Connecting (each remote person)

1. **First time:** get `lexcorp-remote.ovpn` from the company portal (for the demo, the
   stand-in in `company-portal-demo/`), or directly from the administrator.
2. Install **OpenVPN Connect** (<https://openvpn.net/client/>, tested 27 Sept 2026) and
   double-click the profile to import it, or the **OpenVPN Community client 2.6+** ("OpenVPN GUI",
   <https://openvpn.net/community-downloads/>) and use its tray icon's **Import file…**. On macOS,
   Tunnelblick 4 also works. **Phones:** OpenVPN Connect for iOS or Android (tested on a phone,
   27 Sept 2026): open the downloaded profile with it.
3. **Every time:** **Connect**. A browser window opens at the sign-in page and
   sends you to Google. Sign in with an approved account and the VPN connects. Anyone else is
   refused.
4. Open **https://lexcorp-app.duckdns.org** (your `APP_HOST`) and sign in to LexCorp as
   usual. The VPN only gets you to the door; LexCorp's own sign-in and factors still apply.

**One address everywhere, so passkeys work everywhere.** A passkey is tied to the site name it
was created on, a browser rule that stops phishing. So use `https://<APP_HOST>` on the machine
running LexCorp too, not `localhost:5173`. The site proxy also listens on that machine's
loopback address (`127.0.0.1:443`, not reachable from the network); add this line to its hosts
file (Windows: `C:\Windows\System32\drivers\etc\hosts`, as administrator):

```
127.0.0.1 lexcorp-app.duckdns.org
```

A passkey created at `localhost` keeps working only there. In **My identity → Login passkeys**,
people add a passkey on each device they sign in from (PC, laptop, phone; up to 10 per
purpose). Once login is set up, adding or removing one asks for the login authenticator code or
another login passkey, never just the session, and the last login passkey can only be replaced
through an administrator reset. A passkey saved in Google Password Manager or iCloud Keychain
also syncs to the person's other devices; a Windows Hello passkey stays on that PC.

## Day to day

- **Add or remove a person:** edit `ALLOWED_EMAILS` in `.env` (and the Google test users),
  then `docker compose up -d`. Removing someone takes effect at their next connection.
- **See who connected:** on the gateway, `docker compose -f gateway.compose.yml --env-file gateway.env logs auth`
  (each sign-in, the account, accepted or refused).
- **Stop / start:** `docker compose -f <gateway|site>.compose.yml --env-file <gateway|site>.env down` / `up -d`.
- **New site-link keys:** `python scripts/vpn_site_link_keys.py --rotate`, copy `gateway.env` to the gateway, restart both.
- **Start over with new VPN keys:** on the gateway stop, delete `data/openvpn/`, start. Everyone needs the new profile.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| OpenVPN GUI times out, nothing opens | UDP 1194 not open on the gateway (cloud security list and the server's iptables), or the VPN name points to an old IP (gateway `logs duckdns`) |
| Browser opens but the page doesn't load | TCP 9443 not open on the gateway, or its Caddy has no certificate yet (gateway `logs caddy`) |
| Connected, but the app times out | The site link is down: site `logs sitelink` ("no handshake": UDP 51820 blocked on the gateway, or the keys in the two env files don't match) |
| Google: "Error 400: redirect_uri_mismatch" | The redirect URI in Google Cloud must be exactly `https://VPN_HOST:LOGIN_PORT/oauth2/callback` |
| Google: "access blocked" / app not verified | The account isn't a test user on the consent screen |
| Signed in but the VPN still refuses | The email isn't in `ALLOWED_EMAILS` (`docker compose logs auth` says why) |
| Connected but `https://APP_HOST` doesn't resolve | Some routers and DNS filters block public names that point to private addresses. Use another DNS server (e.g. 1.1.1.1) or add `172.30.0.10 lexcorp-app.duckdns.org` to the laptop's hosts file |
| "Blocked request. This host is not allowed" | `REMOTE_APP_ORIGIN` isn't set in `backend/.env`, or `npm start` wasn't restarted |

## What was verified, and what wasn't

Verified locally on 27 Sept 2026 with a test client container:
- the stack starts;
- the sign-in service attaches to OpenVPN;
- a client that can't do browser sign-in is refused;
- a browser-capable client is held pending with the sign-in link, which leads to Google with
  the right client ID, scopes and callback;
- a connected client (sign-in bypassed in the throwaway test setup only) reaches the app
  through Caddy and nothing else: the sign-in service, the management port, plain HTTP and the
  host were all blocked;
- the app receives the client's own VPN address.

Deployed on 27 Sept 2026 with the gateway on an Oracle Cloud VM and the site on the development
machine (behind carrier-grade NAT): the site link is up, the sign-in page is reachable from the
internet with a valid certificate, and the app answers through the site proxy with a valid
certificate. Not yet verified: a real person connecting from outside with a Google sign-in.
