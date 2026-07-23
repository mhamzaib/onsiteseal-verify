# How to verify an OnSiteSeal proof

**Sealed on site. Verifiable anywhere.**

Anyone with a sealed photo pack can confirm integrity in a browser — no OnSiteSeal account, and **no upload to our servers**.

## What you need

From the contractor (via **Share proof pack** in the app):

- A zip containing the sealed JPEG and matching `.receipt.json`, **or**
- Those two files separately

## Steps

1. Open https://mhamzaib.github.io/onsiteseal-verify/verify/
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

Signing mode `software` means device-protected key storage with software Ed25519 (not a hardware secure element). Useful portable integrity — not government-grade attestation.

## What verification does **not** prove

- That the camera was pointed at a particular subject
- That GPS could not be spoofed on a compromised device
- That the device clock was correct
- Identity of the person who held the phone

Use seals as strong documentary evidence, not a substitute for judgment on site context.

## BASIC vs SEALED

- **BASIC** — saved photo; unsigned or seal failed. Documentation only.
- **SEALED** — hash + signature present. Use this verifier for independent checks.

## Privacy

Checks run in your browser with local files. OnSiteSeal does not receive the JPEG or receipt.
