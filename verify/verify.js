/**
 * Client-side OnSiteSeal verifier.
 * Must stay aligned with src/proof canonicalizeClaims + Ed25519 verify.
 */
import * as ed from 'https://esm.sh/@noble/ed25519@3.1.0';
import { sha256, sha512 } from 'https://esm.sh/@noble/hashes@2.2.0/sha2.js';
import JSZip from 'https://esm.sh/jszip@3.10.1';

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

async function loadFromZip(file) {
  const zip = await JSZip.loadAsync(await file.arrayBuffer());
  const names = Object.keys(zip.files).filter((n) => !zip.files[n].dir);
  const jpegName = names.find((n) => /\.jpe?g$/i.test(n));
  const receiptName = names.find((n) => /\.receipt\.json$/i.test(n) || /\.json$/i.test(n));
  if (!jpegName || !receiptName) {
    throw new Error('Zip must contain a JPEG and a .receipt.json');
  }
  const jpegBytes = new Uint8Array(await zip.files[jpegName].async('uint8array'));
  const receiptText = await zip.files[receiptName].async('string');
  return { jpegBytes, receipt: parseReceipt(receiptText), jpegName };
}

async function loadFromDual(jpegFile, receiptFile) {
  const jpegBytes = new Uint8Array(await jpegFile.arrayBuffer());
  const receiptText = await receiptFile.text();
  return { jpegBytes, receipt: parseReceipt(receiptText), jpegName: jpegFile.name };
}

async function verifyBundle(jpegBytes, receipt) {
  const checks = [];
  const photoHash = bytesToHex(sha256(jpegBytes));
  const hashOk = photoHash === receipt.photoHash;
  checks.push({ id: 'hash', ok: hashOk, label: hashOk ? 'Photo hash matches receipt' : 'Photo hash mismatch' });

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
      label: sigOk ? `Signature valid (${receipt.signing})` : 'Signature invalid',
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

function renderResult({ ok, photoHash, checks, receipt, jpegBytes, jpegName }) {
  resultEl.hidden = false;
  resultEl.className = `result ${ok ? 'pass' : 'fail'}`;
  const blob = new Blob([jpegBytes], { type: 'image/jpeg' });
  const url = URL.createObjectURL(blob);
  const gpsLabel = receipt.integritySignals?.gpsLabel ?? null;
  const accuracy =
    receipt.accuracyMeters != null && Number.isFinite(receipt.accuracyMeters)
      ? `±${Math.round(receipt.accuracyMeters)}m`
      : null;

  resultEl.innerHTML = `
    <h2>${ok ? 'Checks passed' : 'Verification failed'}</h2>
    <p class="result-lede">${
      ok
        ? 'Photo hash and signature match the receipt. Files stayed in this browser — nothing was uploaded.'
        : 'One or more checks failed. See details below. Files stayed in this browser.'
    }</p>
    <ul class="checks">
      ${checks
        .map((c) => `<li class="${c.ok ? 'ok' : 'bad'}">${c.ok ? 'PASS' : 'FAIL'} · ${escapeHtml(c.label)}</li>`)
        .join('')}
    </ul>
    <dl>
      <div><dt>Proof code</dt><dd>${escapeHtml(receipt.proofCode ?? '—')}</dd></div>
      <div><dt>Job ID</dt><dd>${escapeHtml(receipt.jobId ?? '—')}</dd></div>
      <div><dt>Captured</dt><dd>${escapeHtml(receipt.capturedAt ?? '—')}</dd></div>
      <div><dt>Location stamp</dt><dd>${escapeHtml(
        gpsLabel ? (accuracy ? `${gpsLabel} (${accuracy})` : gpsLabel) : '—',
      )}</dd></div>
      <div><dt>Photo hash (SHA-256)</dt><dd>${escapeHtml(photoHash)}</dd></div>
      <div><dt>File</dt><dd>${escapeHtml(jpegName ?? 'photo.jpg')}</dd></div>
      <div><dt>Signing</dt><dd>${escapeHtml(receipt.signing ?? '—')}</dd></div>
    </dl>
    <p class="result-note">A pass does not prove subject authenticity, unspoofable GPS, or court admissibility.</p>
    <img class="preview" alt="Selected proof photo" src="${url}" />
  `;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function runVerify() {
  resultEl.hidden = true;
  resultEl.innerHTML = '';
  setStatus('Verifying locally…');
  verifyBtn.disabled = true;

  try {
    let bundle;
    if (zipInput.files?.[0]) {
      bundle = await loadFromZip(zipInput.files[0]);
    } else if (jpegInput.files?.[0] && receiptInput.files?.[0]) {
      bundle = await loadFromDual(jpegInput.files[0], receiptInput.files[0]);
    } else {
      throw new Error('Choose a zip or both JPEG and receipt');
    }

    const outcome = await verifyBundle(bundle.jpegBytes, bundle.receipt);
    renderResult({
      ...outcome,
      receipt: bundle.receipt,
      jpegBytes: bundle.jpegBytes,
      jpegName: bundle.jpegName,
    });
    setStatus(outcome.ok ? 'Done — verified locally; files were not uploaded.' : 'Done — see failures above.');
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
