# Company portal (demonstration stand-in)

A one-page site, hosted free on Vercel, that plays the part of a company's existing employee
portal: you sign in with the company account (Google, for the demo) and download the LexCorp
VPN profile. In a real organisation this download would sit behind its own portal login.

It is **deliberately separate from LexCorp**: LexCorp doesn't trust it or share accounts with
it. It's clearly labelled as a demo and uses no real company's name, branding or look.

How it decides who may download (`lib/authorize.js`, tested in `test/`): the page's "Sign in
with Google" button gives it a Google-signed ID token; `/api/profile` checks the signature
against Google's published keys, that the token was issued for this portal's client ID, and
that the email is verified and on `ALLOWED_EMAILS`. Only then does it return the profile, which
is stored as an encrypted Vercel environment variable, never in git. Downloading the profile
isn't enough to get in anyway: the VPN asks for the Google sign-in again at every connection.

## Deploy (free Vercel Hobby plan)

Prerequisites: the VPN is set up and has written `network/vpn/data/openvpn/client/lexcorp2-remote.ovpn`
(see `network/vpn/README.md`), and you have a Vercel account (sign up with GitHub or Google).

```
cd company-portal-demo
npx vercel login                 # opens the browser once
npx vercel link                  # create the project, e.g. "lexcorp-portal"
```

Add three environment variables (Production):

```
npx vercel env add GOOGLE_CLIENT_ID production        # the same Google client as the VPN
npx vercel env add ALLOWED_EMAILS production          # the same list as network/vpn/.env
```

and the profile, base64-encoded. In PowerShell, from the repository root:

```
[Convert]::ToBase64String([IO.File]::ReadAllBytes("network\vpn\data\openvpn\client\lexcorp2-remote.ovpn")) | npx vercel env add VPN_PROFILE_B64 production
```

Then deploy:

```
npx vercel --prod
```

> **Deploys shown as "Blocked"?** From inside a git repository the Vercel CLI sends the latest
> commit's author, and on the free Hobby plan a deploy is blocked (and that account emailed)
> when the author's email belongs to a Vercel account that isn't in the team. If your Vercel
> login differs from your git identity, deploy from a copy outside the repository: copy `api/`,
> `lib/`, `public/`, `.vercel/`, `package*.json` and `vercel.json` to another folder and run
> `npx vercel deploy --prod` there.

Finally, in Google Cloud (APIs & Services → Credentials → your OAuth client), add the site's
address (e.g. `https://lexcorp-portal.vercel.app`) under **Authorised JavaScript origins**.

If the VPN keys are ever recreated (`network/vpn/data/` deleted), update `VPN_PROFILE_B64` and
redeploy.

## Local checks

```
npm install
npm test
```
