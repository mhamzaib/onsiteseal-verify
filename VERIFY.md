# How to verify an OnSiteSeal proof

**Sealed on site. Verifiable anywhere.**

Anyone with a sealed photo pack can confirm integrity in a browser — no OnSiteSeal account, and **no upload to our servers**.

## What you need

From the contractor (via **Share proof pack** in the app):

- A zip containing:
  - the sealed JPEG, and
  - the matching `.receipt.json` sidecar

Or the two files separately (same names pattern).

## Steps

1. Open the verifier: [https://mhamzaib.github.io/onsiteseal-verify/verify/](https://mhamzaib.github.io/onsiteseal-verify/verify/)
   - **Local:** from the repo root, `npx --yes serve web` then open `/verify/`
2. Drop the zip **or** choose the JPEG + receipt JSON
3. Tap **Verify**

The page checks:

- **Hash** — SHA-256 of the JPEG matches `photoHash` in the receipt
- **Signature** — Ed25519 signature over the receipt claims verifies with the public key inside the receipt

If both pass, the photo bytes and claims have not been altered since sealing.

## What “SEALED” means

| Passes | Meaning |
|--------|---------|
| Hash match | This exact JPEG is the one named in the receipt |
| Signature valid | Claims (time, GPS, job, hash, …) were signed by the device key in the receipt |

Signing mode `software` means the key is device-protected storage + software Ed25519 (not a hardware secure element). That is still useful portable integrity — it is not a government-grade attestation.

## What verification does **not** prove

- That the camera was pointed at a particular wall, meter, or person (“first-mile” / lens aiming)
- That GPS could not be spoofed on a rooted, jailbroken, or otherwise compromised device
- That the contractor’s wall clock was correct (network time hardening is a later epic)
- Identity of the human who held the phone

Use seals as strong documentary evidence, not as a substitute for judgment on site context.

## BASIC vs SEALED

- **BASIC** — photo saved; hash/sign failed or unsigned. Still useful documentation; not cryptographically sealed.
- **SEALED** — hash + signature present. Use the verifier for independent checks.

## Privacy

The static verifier runs in your browser with local files. OnSiteSeal does not receive the JPEG or receipt when you verify this way.

## Links

- Verifier: https://mhamzaib.github.io/onsiteseal-verify/verify/
- Public site repo: https://github.com/mhamzaib/onsiteseal-verify
- Source (app): https://github.com/mhamzaib/onsiteseal
- Architecture notes: [`ARCHITECTURE.md`](ARCHITECTURE.md)
