# How to verify an OnSiteSeal proof

**Sealed on site. Verifiable anywhere.**

Anyone with a sealed photo pack can confirm integrity in a browser — no OnSiteSeal account, and **no upload to our servers**. The verifier page is self-contained (no CDN) and offline-capable once loaded or saved.

## What you need

- A **single-photo** zip (JPEG + `.receipt.json`), or
- A **whole-job** zip (`manifest.json` + every photo + matching receipts), or
- JPEG + receipt chosen separately

## Steps

1. Open https://mhamzaib.github.io/onsiteseal-verify/verify/ (or local `/verify/`)
2. Drop the zip **or** choose the JPEG + receipt JSON
3. Tap **Verify locally**

Every JPEG+receipt pair in a job pack is checked. Overall pass = all pairs passed. A photo without a matching receipt fails the pack (the page will not silently verify only the first file).

## Trust limits

A pass proves internal consistency with the **public key inside each receipt**. It does not prove the key came from a genuine OnSiteSeal install or hardware attestation — a replaced photo+receipt pair signed with any key can still pass. ATTESTED is not shipped.

## What verification does not prove

Subject authenticity, unspoofable GPS, correct clock, who held the phone, court admissibility.

## Privacy

Checks run in your browser with local files. OnSiteSeal does not receive the JPEG or receipt.
