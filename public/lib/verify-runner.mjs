// verify-runner.mjs — pure DOM-free verification logic.
// Used by verify.js (UI) and artifacts.js (library badge row re-verify).
// No document/window/location/DOM references.

import { parseTstDer, bytesHex, bytesToBase64, base64ToBytes, verifyTstBinding } from '/js/tst.js';
import { verifyExecutionHash, verifySignature, verifyComputeProof } from '/vendor/ocg/verify.mjs';

// Verify a DER TimeStampToken/TimeStampResp against a known hash and TSA.
// logOrigin is required to select the pinned root for chain validation.
// Returns { ok, tsa, genTime, policyOid, serial, reasons }
export async function verifyRfc3161Tst(derBytes, artifactHashHex, logOrigin) {
  const hashHex = (artifactHashHex || '').replace(/^sha256:/, '');
  const bytes = derBytes instanceof Uint8Array ? derBytes : new Uint8Array(derBytes);
  const proof = bytesToBase64(bytes);
  const binding = {
    type: 'rfc3161-tst',
    anchored_hash: 'sha256:' + hashHex,
    log_origin: logOrigin || '',
    proof,
  };
  const r = await verifyTstBinding(binding);
  if (!r.ok) {
    return { ok: false, tsa: logOrigin || '', error: r.error, reasons: [r.error] };
  }
  return {
    ok: true,
    tsa: logOrigin || '',
    genTime: r.genTime,
    policyOid: r.policy,
    serial: r.serial,
    reasons: [],
  };
}

// Parse a raw DER without chain validation (for unknown-authority drops).
// Returns { ok, genTime, policyOid, serial, stampedHash, certCount } or { ok:false, error }
export function parseRfc3161Tst(derBytes) {
  try {
    const bytes = derBytes instanceof Uint8Array ? derBytes : new Uint8Array(derBytes);
    const { tstInfo, signed } = parseTstDer(bytes);
    const imprint = bytesHex(new Uint8Array(tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView));
    return {
      ok: true,
      genTime: tstInfo.genTime.toISOString(),
      policyOid: tstInfo.policy,
      serial: bytesHex(new Uint8Array(tstInfo.serialNumber.valueBlock.valueHexView)),
      stampedHash: 'sha256:' + imprint,
      certCount: (signed.certificates || []).length,
    };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// Verify an OpenTimestamps proof against a hash.
// Returns { ok, status:'pending'|'complete'|'error', genTime?, error? }
export async function verifyOts(otsBytes, hashHex) {
  const OT = globalThis.OpenTimestamps;
  if (!OT) return { ok: false, status: 'error', error: 'OpenTimestamps library not available' };

  const hex = (hashHex || '').replace(/^sha256:/, '');
  const hashBytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hashBytes.length; i++) hashBytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);

  let fileOts;
  try {
    const bytes = otsBytes instanceof Uint8Array ? otsBytes : new Uint8Array(otsBytes);
    fileOts = OT.DetachedTimestampFile.deserialize(bytes);
  } catch (e) {
    return { ok: false, status: 'error', error: 'Cannot parse OTS proof: ' + e.message };
  }

  const fileHash = OT.DetachedTimestampFile.fromHash(new OT.Ops.OpSHA256(), hashBytes);

  try {
    const result = await OT.verify(fileOts, fileHash);
    if (result !== null && result !== undefined) {
      const ts = typeof result === 'number' ? new Date(result * 1000).toISOString() : String(result);
      return { ok: true, status: 'complete', genTime: ts };
    }
    return { ok: false, status: 'pending' };
  } catch (e) {
    const msg = e?.message || String(e);
    if (msg.toLowerCase().includes('pending') || msg.toLowerCase().includes('calendar')) {
      return { ok: false, status: 'pending' };
    }
    return { ok: false, status: 'error', error: msg };
  }
}

// Verify an OCG artifact: section 4 hash, section 16 sig, section 18 proof, section 20 anchors.
// Returns { hash, sig, proof, anchors[] }
// Each field: { status:'ok'|'fail'|'skip', ...details }
export async function verifyOcgArtifact(json) {
  const out = { hash: null, sig: null, proof: null, anchors: [] };

  // Section 4: execution hash recompute
  try {
    const r = await verifyExecutionHash(json);
    out.hash = { status: r.valid ? 'ok' : 'fail', computed: r.computed_hash, claimed: r.claimed_hash };
  } catch (e) {
    out.hash = { status: 'fail', detail: e.message };
  }

  // Section 16: eddsa-jcs-2022 signature (optional)
  if (json.audit_signature?.proof) {
    try {
      const valid = await verifySignature(json);
      out.sig = {
        status: valid ? 'ok' : 'fail',
        vm: json.audit_signature.proof.verificationMethod || 'n/a',
      };
    } catch (e) {
      out.sig = { status: 'fail', detail: e.message };
    }
  } else {
    out.sig = { status: 'skip' };
  }

  // Section 18: Groth16-BN254 compute proof (optional)
  if (json.audit_signature?.compute_proof) {
    try {
      const valid = verifyComputeProof(json);
      out.proof = {
        status: valid ? 'ok' : 'fail',
        fmt: json.audit_signature.compute_proof.receiptFormat || 'n/a',
      };
    } catch (e) {
      out.proof = { status: 'fail', detail: e.message };
    }
  } else {
    out.proof = { status: 'skip' };
  }

  // Section 20: anchor bindings (optional)
  if (Array.isArray(json.anchor_bindings)) {
    for (const b of json.anchor_bindings) {
      if (b.type === 'rfc3161-tst') {
        try {
          const derBytes = base64ToBytes(b.proof);
          const r = await verifyRfc3161Tst(derBytes, b.anchored_hash, b.log_origin);
          out.anchors.push({ type: 'rfc3161-tst', logOrigin: b.log_origin, ...r });
        } catch (e) {
          out.anchors.push({ type: 'rfc3161-tst', logOrigin: b.log_origin, ok: false, error: e.message, reasons: [e.message] });
        }
      } else if (b.type === 'opentimestamps') {
        try {
          const otsBytes = base64ToBytes(b.proof);
          const r = await verifyOts(otsBytes, b.anchored_hash);
          out.anchors.push({ type: 'opentimestamps', logOrigin: 'bitcoin', ...r });
        } catch (e) {
          out.anchors.push({ type: 'opentimestamps', logOrigin: 'bitcoin', ok: false, status: 'error', error: e.message });
        }
      } else {
        out.anchors.push({ type: b.type || 'unknown', ok: false, status: 'error', error: 'Unsupported binding type' });
      }
    }
  }

  return out;
}
