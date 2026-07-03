// library-bridge.mjs — IndexedDB persistence for OCG artifacts and anchor receipts.
// idb-keyval UMD must be loaded as <script> before any module that imports this file.
// globalThis.idbKeyval is set by the UMD when it loads.

const DB_NAME = 'anchor-suite-library';
const STORE_NAME = 'artifacts';
const BROADCAST_CH = 'ocg-library';

let _store = null;

function idb() { return globalThis.idbKeyval || null; }

function store() {
  if (!_store) {
    const lib = idb();
    if (lib?.createStore) _store = lib.createStore(DB_NAME, STORE_NAME);
  }
  return _store;
}

function storageKey(parsed) {
  if (typeof parsed?.execution_hash === 'string') {
    return 'ocg:' + parsed.execution_hash.replace(/^sha256:/, '');
  }
  const first = Array.isArray(parsed?.anchor_bindings) ? parsed.anchor_bindings[0] : null;
  if (typeof first?.anchored_hash === 'string') {
    return 'anchor:' + first.anchored_hash.replace(/^sha256:/, '');
  }
  // Fallback: timestamp-based key (not ideal but avoids silent data loss)
  return 'misc:' + Date.now().toString(36);
}

function deriveTags(parsed) {
  const tags = [];
  if (parsed?.execution_hash) tags.push('ocg');
  if (!parsed?.execution_hash && Array.isArray(parsed?.anchor_bindings)) tags.push('anchors');
  if (Array.isArray(parsed?.anchor_bindings)) {
    for (const b of parsed.anchor_bindings) {
      if (b.type === 'rfc3161-tst') {
        const o = (b.log_origin || '').toLowerCase();
        if (o.includes('sigstore')) { tags.push('sigstore'); continue; }
        if (o.includes('digicert')) { tags.push('digicert'); continue; }
        if (o.includes('sectigo')) { tags.push('sectigo'); continue; }
        if (o.includes('freetsa')) { tags.push('freetsa'); continue; }
        if (o.includes('github')) { tags.push('github'); continue; }
        tags.push('rfc3161');
      } else if (b.type === 'opentimestamps') {
        tags.push('ots');
      }
    }
  }
  return [...new Set(tags)];
}

function broadcast(msg) {
  try { new BroadcastChannel(BROADCAST_CH).postMessage(msg); } catch { /* ignore */ }
}

// Save an artifact to the library. Returns the storage key, or null if storage unavailable.
export async function saveToLibrary(rawText, parsed) {
  const lib = idb();
  const s = store();
  if (!lib || !s) return null;

  const key = storageKey(parsed);
  const existing = await lib.get(key, s).catch(() => null);
  const record = {
    key,
    rawText,
    parsed,
    addedAt: existing?.addedAt ?? Date.now(),
    pinned: existing?.pinned ?? false,
    pinnedIndex: existing?.pinnedIndex ?? 0,
    tags: deriveTags(parsed),
  };
  await lib.set(key, record, s);
  broadcast({ type: 'added', key });
  return key;
}

// Load all records from the library.
export async function loadLibrary() {
  const lib = idb();
  const s = store();
  if (!lib || !s) return [];
  return lib.values(s).catch(() => []);
}

// Get a single record by key.
export async function getRecord(key) {
  const lib = idb();
  const s = store();
  if (!lib || !s) return null;
  return lib.get(key, s).catch(() => null);
}

// Partial update: merge `updates` into the existing record.
export async function updateRecord(key, updates) {
  const lib = idb();
  const s = store();
  if (!lib || !s) return;
  const existing = await lib.get(key, s).catch(() => null);
  if (existing) {
    await lib.set(key, { ...existing, ...updates }, s);
    broadcast({ type: 'updated', key });
  }
}

// Delete a record.
export async function deleteRecord(key) {
  const lib = idb();
  const s = store();
  if (!lib || !s) return;
  await lib.del(key, s).catch(() => {});
  broadcast({ type: 'deleted', key });
}

// Subscribe to library events from other tabs. Returns an unsubscribe function.
export function subscribeLibrary(callback) {
  try {
    const ch = new BroadcastChannel(BROADCAST_CH);
    ch.addEventListener('message', (e) => callback(e.data));
    return () => ch.close();
  } catch {
    return () => {};
  }
}
