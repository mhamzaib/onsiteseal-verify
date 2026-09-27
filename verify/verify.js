/**
 * Client-side OnSiteSeal verifier.
 * Must stay aligned with src/proof canonicalizeClaims + Ed25519 verify.
 *
 * Source module — bundle with `npm run build:verifier` into verify.bundle.js
 * so Pages can verify offline without esm.sh / CDN.
 */
import * as ed from '@noble/ed25519';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import JSZip from 'jszip';

ed.hashes.sha512 = sha512;
ed.hashes.sha512Async = async (message) => sha512(message);

const SCHEMA_VERSION = 1;

const zipInput = document.getElementById('zipInput');
const jpegInput = document.getElementById('jpegInput');
const receiptInput = document.getElementById('receiptInput');
const verifyBtn = document.getElementById('verifyBtn');
const statusEl = document.getElementById('status');
const resultEl = document.getElementById('result');

function setStatus(text) {
  statusEl.textContent = text;
}

function refreshReady() {
  const zipReady = Boolean(zipInput.files?.[0]);
  const dualReady = Boolean(jpegInput.files?.[0] && receiptInput.files?.[0]);
  verifyBtn.disabled = !(zipReady || dualReady);
}

zipInput.addEventListener('change', () => {
  if (zipInput.files?.[0]) {
    jpegInput.value = '';
    receiptInput.value = '';
  }
  refreshReady();
});

[jpegInput, receiptInput].forEach((el) => {
  el.addEventListener('change', () => {
    if (jpegInput.files?.[0] || receiptInput.files?.[0]) {
      zipInput.value = '';
    }
    refreshReady();
  });
});

verifyBtn.addEventListener('click', () => {
  void runVerify();
});

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const normalized = hex.trim().toLowerCase();
  if (normalized.length % 2 !== 0) throw new Error('Invalid hex length');
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const byte = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error('Invalid hex');
    out[i] = byte;
  }
  return out;
}

/** Keep in lockstep with src/proof/hash.ts canonicalizeClaims */
function canonicalizeClaims(claims) {
  return JSON.stringify({
    schemaVersion: claims.schemaVersion,
    proofCode: claims.proofCode,
    photoHash: claims.photoHash,
    capturedAt: claims.capturedAt,
    jobId: claims.jobId,
    latitude: claims.latitude,
    longitude: claims.longitude,
    accuracyMeters: claims.accuracyMeters,
    address: claims.address,
    appVersion: claims.appVersion,
    platform: claims.platform,
    integritySignals: {
      reasons: [...claims.integritySignals.reasons].sort(),
      severity: claims.integritySignals.severity,
      gpsLabel: claims.integritySignals.gpsLabel,
    },
  });
}

function claimsFromReceipt(receipt) {
  return {
    schemaVersion: receipt.schemaVersion,
    proofCode: receipt.proofCode,
    photoHash: receipt.photoHash,
    capturedAt: receipt.capturedAt,
    jobId: receipt.jobId,
    latitude: receipt.latitude,
    longitude: receipt.longitude,
    accuracyMeters: receipt.accuracyMeters,
    address: receipt.address,
    appVersion: receipt.appVersion,
    platform: receipt.platform,
    integritySignals: receipt.integritySignals,
  };
}

function parseReceipt(jsonText) {
  const receipt = JSON.parse(jsonText);
  if (!receipt || typeof receipt !== 'object') throw new Error('Invalid receipt JSON');
  if (receipt.schemaVersion !== SCHEMA_VERSION) {
    throw new Error(`Unsupported receipt schema v${receipt.schemaVersion}`);
  }
  if (typeof receipt.photoHash !== 'string' || typeof receipt.signing !== 'string') {
    throw new Error('Receipt missing required fields');
  }
  return receipt;
}

function basename(path) {
  const parts = path.replace(/\\/g, '/').split('/');
  return parts[parts.length - 1] || path;
}

function stemFromJpeg(name) {
  return basename(name).replace(/\.jpe?g$/i, '');
}

function receiptStem(name) {
  const base = basename(name);
  if (/\.receipt\.json$/i.test(base)) {
    return base.replace(/\.receipt\.json$/i, '');
  }
  if (/\.json$/i.test(base) && !/manifest\.json$/i.test(base) && !/data\.json$/i.test(base)) {
    return base.replace(/\.json$/i, '');
  }
  return null;
}

/**
 * Pair every JPEG with a matching receipt by stem (supports job packs).
 * Ignores manifest.json / data.json. Throws if any JPEG lacks a receipt.
 */
function pairZipEntries(names) {
  const files = names.filter(
    (n) =>
      !n.endsWith('/') &&
      !/\/manifest\.json$/i.test(n) &&
      !/^manifest\.json$/i.test(n) &&
      !/\/data\.json$/i.test(n) &&
      !/^data\.json$/i.test(n),
  );
  const jpegs = files.filter((n) => /\.jpe?g$/i.test(n)).sort();
  const receipts = files.filter(
    (n) => /\.receipt\.json$/i.test(n) || (/\.json$/i.test(n) && receiptStem(n)),
  );

  if (jpegs.length === 0) {
    throw new Error('Zip must contain at least one JPEG');
  }

  const receiptByStem = new Map();
  for (const path of receipts) {
    const stem = receiptStem(path);
    if (stem) receiptByStem.set(stem.toLowerCase(), path);
  }

  const pairs = [];
  const missing = [];
  for (const jpegPath of jpegs) {
    const stem = stemFromJpeg(jpegPath).toLowerCase();
    const receiptPath = receiptByStem.get(stem);
    if (!receiptPath) {
      missing.push(basename(jpegPath));
      continue;
    }
    pairs.push({ jpegPath, receiptPath });
  }

  if (pairs.length === 0) {
    throw new Error('Zip must contain matching JPEG + .receipt.json pairs');
  }
  if (missing.length > 0) {
    throw new Error(
      `Missing receipt for: ${missing.join(', ')}. Every photo in the pack needs a matching .receipt.json.`,
    );
  }
  return pairs;
}

async function loadPairsFromZip(file) {
  const zip = await JSZip.loadAsync(await file.arrayBuffer());
  const names = Object.keys(zip.files).filter((n) => !zip.files[n].dir);
  const hasManifest = names.some((n) => /(^|\/)manifest\.json$/i.test(n));
  const pairsMeta = pairZipEntries(names);
  const pairs = [];
  for (const { jpegPath, receiptPath } of pairsMeta) {
    const jpegBytes = new Uint8Array(await zip.files[jpegPath].async('uint8array'));
    const receiptText = await zip.files[receiptPath].async('string');
    pairs.push({
      jpegBytes,
      receipt: parseReceipt(receiptText),
      jpegName: basename(jpegPath),
    });
  }
  return { pairs, jobPack: hasManifest || pairs.length > 1 };
}

async function loadFromDual(jpegFile, receiptFile) {
  const jpegBytes = new Uint8Array(await jpegFile.arrayBuffer());
  const receiptText = await receiptFile.text();
  return {
    pairs: [
      {
        jpegBytes,
        receipt: parseReceipt(receiptText),
        jpegName: jpegFile.name,
      },
    ],
    jobPack: false,
  };
}

async function verifyBundle(jpegBytes, receipt) {
  const checks = [];
  const photoHash = bytesToHex(sha256(jpegBytes));
  const hashOk = photoHash === receipt.photoHash;
  checks.push({
    id: 'hash',
    ok: hashOk,
    label: hashOk ? 'Photo hash matches receipt' : 'Photo hash mismatch',
  });

  let sigOk = false;
  if (receipt.signing === 'none' || !receipt.signature || !receipt.publicKey) {
    checks.push({ id: 'sig', ok: false, label: 'Receipt is unsigned (BASIC)' });
  } else {
    const message = new TextEncoder().encode(canonicalizeClaims(claimsFromReceipt(receipt)));
    sigOk = await ed.verifyAsync(
      hexToBytes(receipt.signature),
      message,
      hexToBytes(receipt.publicKey),
    );
    checks.push({
      id: 'sig',
      ok: sigOk,
      label: sigOk
        ? `Signature valid (${receipt.signing}) — key from this receipt`
        : 'Signature invalid',
    });
  }

  const schemaOk = receipt.schemaVersion === SCHEMA_VERSION;
  checks.push({
    id: 'schema',
    ok: schemaOk,
    label: schemaOk ? `Schema v${SCHEMA_VERSION}` : 'Schema mismatch',
  });

  return {
    ok: hashOk && sigOk && schemaOk,
    photoHash,
    checks,
  };
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderMultiResult({ items, jobPack }) {
  const allOk = items.every((item) => item.ok);
  const publicKeys = [
    ...new Set(
      items
        .map((item) => item.receipt.publicKey)
        .filter((k) => typeof k === 'string' && k.length > 0),
    ),
  ];
  const keyNote =
    items.length > 1
      ? publicKeys.length <= 1
        ? 'All photos in this pack share one signing public key (consistent with one device install).'
        : `Warning: ${publicKeys.length} different signing keys in this pack — not a single-device seal set.`
      : null;

  resultEl.hidden = false;
  resultEl.className = `result ${allOk ? 'pass' : 'fail'}`;

  const summary = jobPack
    ? allOk
      ? `All ${items.length} photos in this job pack passed hash + signature checks.`
      : `${items.filter((i) => i.ok).length} of ${items.length} photos passed. Failures listed below.`
    : allOk
      ? 'Photo hash and signature match the receipt. Files stayed in this browser — nothing was uploaded.'
      : 'One or more checks failed. See details below. Files stayed in this browser.';

  const cards = items
    .map((item) => {
      const blob = new Blob([item.jpegBytes], { type: 'image/jpeg' });
      const url = URL.createObjectURL(blob);
      const gpsLabel = item.receipt.integritySignals?.gpsLabel ?? null;
      const accuracy =
        item.receipt.accuracyMeters != null && Number.isFinite(item.receipt.accuracyMeters)
          ? `±${Math.round(item.receipt.accuracyMeters)}m`
          : null;
      return `
      <article class="pair ${item.ok ? 'pair-ok' : 'pair-bad'}">
        <h3>${item.ok ? 'PASS' : 'FAIL'} · ${escapeHtml(item.jpegName)}</h3>
        <ul class="checks">
          ${item.checks
            .map(
              (c) =>
                `<li class="${c.ok ? 'ok' : 'bad'}">${c.ok ? 'PASS' : 'FAIL'} · ${escapeHtml(c.label)}</li>`,
            )
            .join('')}
        </ul>
        <dl>
          <div><dt>Proof code</dt><dd>${escapeHtml(item.receipt.proofCode ?? '—')}</dd></div>
          <div><dt>Job ID</dt><dd>${escapeHtml(item.receipt.jobId ?? '—')}</dd></div>
          <div><dt>Captured</dt><dd>${escapeHtml(item.receipt.capturedAt ?? '—')}</dd></div>
          <div><dt>Location stamp</dt><dd>${escapeHtml(
            gpsLabel ? (accuracy ? `${gpsLabel} (${accuracy})` : gpsLabel) : '—',
          )}</dd></div>
          <div><dt>Photo hash (SHA-256)</dt><dd>${escapeHtml(item.photoHash)}</dd></div>
          <div><dt>Signing</dt><dd>${escapeHtml(item.receipt.signing ?? '—')}</dd></div>
        </dl>
        <img class="preview" alt="Proof photo ${escapeHtml(item.jpegName)}" src="${url}" />
      </article>`;
    })
    .join('');

  resultEl.innerHTML = `
    <h2>${allOk ? 'Checks passed' : 'Verification failed'}${
      jobPack || items.length > 1 ? ` · ${items.length} photos` : ''
    }</h2>
    <p class="result-lede">${escapeHtml(summary)}</p>
    ${keyNote ? `<p class="result-note">${escapeHtml(keyNote)}</p>` : ''}
    <p class="result-note">
      A pass proves this JPEG matches its receipt hash and the claims were signed by the
      <strong>public key inside that receipt</strong>. It does not prove the key came from a
      genuine OnSiteSeal install, hardware attestation, or that an attacker could not replace
      both the photo and receipt with a freshly signed pair. Files stayed in this browser.
    </p>
    <p class="result-note">A pass also does not prove subject authenticity, unspoofable GPS, or court admissibility.</p>
    <div class="pair-list">${cards}</div>
  `;
}

async function runVerify() {
  resultEl.hidden = true;
  resultEl.innerHTML = '';
  setStatus('Verifying locally…');
  verifyBtn.disabled = true;

  try {
    let loaded;
    if (zipInput.files?.[0]) {
      loaded = await loadPairsFromZip(zipInput.files[0]);
    } else if (jpegInput.files?.[0] && receiptInput.files?.[0]) {
      loaded = await loadFromDual(jpegInput.files[0], receiptInput.files[0]);
    } else {
      throw new Error('Choose a zip or both JPEG and receipt');
    }

    setStatus(
      loaded.pairs.length > 1
        ? `Checking ${loaded.pairs.length} photos in pack…`
        : 'Verifying locally…',
    );

    const items = [];
    for (const pair of loaded.pairs) {
      const outcome = await verifyBundle(pair.jpegBytes, pair.receipt);
      items.push({
        ...outcome,
        receipt: pair.receipt,
        jpegBytes: pair.jpegBytes,
        jpegName: pair.jpegName,
      });
    }

    renderMultiResult({ items, jobPack: loaded.jobPack });
    const allOk = items.every((i) => i.ok);
    setStatus(
      allOk
        ? loaded.pairs.length > 1
          ? `Done — all ${items.length} photos verified locally; files were not uploaded.`
          : 'Done — verified locally; files were not uploaded.'
        : 'Done — see failures above.',
    );
  } catch (err) {
    setStatus(err instanceof Error ? err.message : 'Verification failed');
    resultEl.hidden = false;
    resultEl.className = 'result fail';
    resultEl.innerHTML = `<h2>Could not verify</h2><p>${escapeHtml(
      err instanceof Error ? err.message : 'Unknown error',
    )}</p>`;
  } finally {
    refreshReady();
  }
}
