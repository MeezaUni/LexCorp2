# Remote access: VPN with company sign-in on every connection

LexCorp2 is never published on the internet. People on the company network reach it directly.
People outside connect through this VPN, and **every connection requires signing in with the
company's existing login**. For this demonstration, the company login is played by
**Sign in with Google**, restricted to an allowlist of accounts.

```
                 (1) first time: company portal -> download lexcorp2-remote.ovpn
                                  (demo stand-in: company-portal-demo/, on Vercel)

 remote laptop                           this machine (Docker)
 OpenVPN GUI --- UDP VPN_PORT ---------> openvpn 172.30.0.2 --(only HTTPS)--> caddy 172.30.0.10 --> LexCorp2 (Vite :5173)
     |                                        |
     | (2) every connection: browser opens    | "who is this?"
     v                                        v
 https://VPN_HOST:LOGIN_PORT --- TCP -----> caddy --> auth 172.30.0.3 --> Google: signed in? on ALLOWED_EMAILS?
                                                                           yes -> connected, no -> refused
 (3) connected: open https://APP_HOST  (resolves to 172.30.0.10, reachable only through the VPN)
```

- **OpenVPN Community Edition** (free, no connection limit) with **openvpn-auth-oauth2**
  (open source, MIT), which asks the identity provider at every connection. In a company,
  Google is replaced by the company's own provider (Microsoft Entra ID, AD FS, Keycloak...),
  the same OIDC standard with a different issuer, client ID and secret.
- **Allowlist:** a connection is accepted only for a Google account whose email is verified
  and listed in `ALLOWED_EMAILS`. Anyone else is refused before reaching the network.
- **A client that can't do the browser sign-in is refused**, even with the profile. The profile's
  certificate is required too, but it identifies the device, not the person.
- **Split tunnel, least privilege:** a connected person gets one route, to the LexCorp2 proxy
  (HTTPS only). The VPN server, the sign-in service, this machine and the rest of the network
  are unreachable through the VPN. Their own internet traffic doesn't go through it.
- **Real HTTPS for the app:** passkeys and the browser's cryptography only work on HTTPS.
  Caddy gets free Let's Encrypt certificates through DuckDNS (DNS challenge), so the app's
  VPN-only name has a valid certificate without being reachable from the internet.
- **Audit trail:** LexCorp2 sees each remote person's own VPN address (10.8.0.x). It isn't
  translated away, so the audit trail and the risk model's "new network address" check work.
- **Cost: none.** OpenVPN, openvpn-auth-oauth2, Caddy, DuckDNS, Let's Encrypt, a Google OAuth
  client (testing mode, up to 100 listed users) and the OpenVPN GUI client are all free.

Only two ports are opened on the router: the VPN (UDP) and the sign-in page (TCP). The app
itself is never exposed.

## Setup (once)

### 1. DuckDNS: two names and a token

1. Sign in at <https://www.duckdns.org> (you can use your Google account).
2. Add two domains, for example `lexcorp2-vpn` and `lexcorp2-app`. Names are first come,
   first served, so pick others if these are taken.
3. Copy the **token** shown at the top of the page.

The `duckdns` service keeps them up to date by itself: the VPN name follows this network's
public IP (which changes), and the app name points to the proxy's private address `172.30.0.10`.

### 2. Google sign-in client

1. Open <https://console.cloud.google.com>, create a project (for example "LexCorp2 VPN").
2. **APIs & Services → OAuth consent screen:** choose **External**, app name "LexCorp2 VPN
   (demo)", your email as support and developer contact. Leave it in **Testing** mode.
   Under **Test users**, add every account that should be able to connect. In testing mode
   Google only lets these accounts sign in at all: a second lock on top of `ALLOWED_EMAILS`.
3. **APIs & Services → Credentials → Create credentials → OAuth client ID**, type **Web
   application**, name "LexCorp2 VPN sign-in".
   - **Authorised redirect URIs:** `https://<VPN_HOST>:<LOGIN_PORT>/oauth2/callback`,
     for example `https://lexcorp2-vpn.duckdns.org:9443/oauth2/callback`.
   - If you will also use the demo company portal (`company-portal-demo/`), add its address
     under **Authorised JavaScript origins**, for example `https://lexcorp2-portal.vercel.app`.
4. Copy the **Client ID** and **Client secret**.

### 3. `network/vpn/.env`

Copy `.env.example` to `.env` (git-ignored) and fill in the two DuckDNS names, the token, the
Google client ID and secret, and `ALLOWED_EMAILS` (comma-separated).

### 4. Router: forward two ports to this machine

In the router's admin page (often `http://192.168.1.1`), forward to this machine's local
address (Windows: `ipconfig`, "IPv4 Address" of the Wi-Fi or Ethernet adapter):

| Port | Protocol | Purpose |
|---|---|---|
| `VPN_PORT` (1194) | UDP | the VPN |
| `LOGIN_PORT` (9443) | TCP | the sign-in page |

Give this machine a fixed local address (a DHCP reservation in the router) so the forwarding
keeps working. Allow Docker Desktop through the Windows firewall if Windows asks.

> **Check for carrier-grade NAT.** The router's status page shows its WAN (internet) address.
> If it doesn't match <https://api.ipify.org>, or starts with `100.64`–`100.127` or `10.`,
> your provider shares one public address between customers and nothing hosted at home can be
> reached from outside. Ask the provider for a public IPv4 address. It is often free on request.

### 5. Tell LexCorp2 its VPN address

In `backend/.env` add:

```
REMOTE_APP_ORIGIN=https://lexcorp2-app.duckdns.org
```

(your `APP_HOST`), then restart `npm start`. This adds the name to the allowed origins, lets
Vite answer for it, and makes passkeys created there belong to that name.

### 6. Start the VPN

```
cd network/vpn
docker compose up -d --build
docker compose logs -f           # Ctrl+C to stop watching
```

On first start it creates the certificate authority, keys and the client profile
`network/vpn/data/client/lexcorp2-remote.ovpn`. Caddy may take a minute to get its certificates.

## Connecting (each remote person)

1. **First time:** get `lexcorp2-remote.ovpn` from the company portal (for the demo, the
   stand-in in `company-portal-demo/`), or directly from the administrator.
2. Install the **OpenVPN Community client for Windows 2.6 or later** ("OpenVPN GUI",
   <https://openvpn.net/community-downloads/>). OpenVPN Connect only partly supports the
   browser sign-in. On macOS use Tunnelblick 4.
3. Right-click the OpenVPN GUI tray icon → **Import file…** → choose the profile.
4. **Every time:** right-click → **Connect**. A browser window opens at the sign-in page and
   sends you to Google. Sign in with an approved account and the VPN connects. Anyone else is
   refused.
5. Open **https://lexcorp2-app.duckdns.org** (your `APP_HOST`) and sign in to LexCorp2 as
   usual. The VPN only gets you to the door; LexCorp2's own sign-in and factors still apply.

**Passkeys belong to the address they were created on.** A passkey made on `localhost` (on
this machine) doesn't work at the VPN address, and vice versa. Remotely, sign in with the
authenticator code, then add a passkey for the VPN address in **My identity** if you want one.
Each person can have one passkey per purpose per address.

## Day to day

- **Add or remove a person:** edit `ALLOWED_EMAILS` in `.env` (and the Google test users),
  then `docker compose up -d`. Removing someone takes effect at their next connection.
- **See who connected:** `docker compose logs auth` (each sign-in, the account, accepted or refused).
- **Stop:** `docker compose down`. **Start again:** `docker compose up -d`.
- **Start over with new keys:** stop, delete `network/vpn/data/`, start. Everyone needs the new profile.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| OpenVPN GUI times out, nothing opens | UDP `VPN_PORT` not forwarded, carrier-grade NAT, or the VPN name points to an old IP (check `docker compose logs duckdns`) |
| Browser opens but the page doesn't load | TCP `LOGIN_PORT` not forwarded, or Caddy has no certificate yet (`docker compose logs caddy`) |
| Google: "Error 400: redirect_uri_mismatch" | The redirect URI in Google Cloud must be exactly `https://VPN_HOST:LOGIN_PORT/oauth2/callback` |
| Google: "access blocked" / app not verified | The account isn't a test user on the consent screen |
| Signed in but the VPN still refuses | The email isn't in `ALLOWED_EMAILS` (`docker compose logs auth` says why) |
| Connected but `https://APP_HOST` doesn't resolve | Some routers and DNS filters block public names that point to private addresses. Use another DNS server (e.g. 1.1.1.1) or add `172.30.0.10 lexcorp2-app.duckdns.org` to the laptop's hosts file |
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

Not yet verified: a real Google sign-in and a connection from outside through the router,
which need the accounts and port forwarding above.
