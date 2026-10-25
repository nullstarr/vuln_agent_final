// Bruecke zwischen unserer Python-Pipeline und der ECHTEN Meterless-World-Model-Referenz.
//
// Protokoll: eine JSON-Zeile pro Anfrage auf stdin, eine JSON-Zeile pro Antwort auf stdout.
//   Anfrage : {"id": 1, "cmd": "assertFact", "args": {...}}
//   Antwort : {"id": 1, "ok": true, "result": ...}   oder   {"id": 1, "ok": false, "error": "..."}
// Befehle: init, idFor, upsertEntity, ingest, relate, assertFact, snapshot, entityAt
//
// Die Engine selbst (world-model.mjs) ist die UNVERAENDERTE Meterless-Referenz, nur mit esbuild zu einer
// Datei gebuendelt - siehe NOTICE.md. Diese Bruecke enthaelt keine eigene Fachlogik.

import readline from "node:readline";
import { WorldModel, entityIdFromName } from "./world-model.mjs";

let wm = null;
let cfg = {};

function need() {
  if (!wm) throw new Error("init zuerst aufrufen");
  return wm;
}

const handlers = {
  // storage "local" + directory: der Zustand liegt in <directory>/.world/<namespace>.json und wird beim naechsten
  // Start wieder geladen (fortsetzbar). Ist die Datei unlesbar, wirft der Konstruktor - die Python-Seite stellt sie
  // dann unter Quarantaene und baut aus den Quellen neu auf (siehe agents/meterless_bridge.py).
  async init({ namespace, conflictPolicy, sourcePriority, storage, directory }) {
    cfg = { conflictPolicy, sourcePriority };
    wm = new WorldModel({ namespace, storage: storage ?? "memory", directory, conflictPolicy, sourcePriority });
    return { engine: "meterless-world-model-reference", node: process.version };
  },

  async idFor({ type, name }) {
    return entityIdFromName(type, name);
  },

  async upsertEntity({ type, name, kind, by, at }) {
    const e = await need().upsertEntity({ type, name, source: { kind, by, at } });
    return { id: e.id, name: e.name, type: e.type, state: e.state };
  },

  // Meterless' kanonischer Einlese-Weg: wiederholbar (gleicher Stapel zweimal = leere Aenderung, erkannt an einer
  // Pruefsumme). Gibt den Laufbericht zurueck.
  async ingest({ observations }) {
    const r = await need().ingest(observations);
    return { runId: r.runId, processed: r.processed, skippedUnchanged: r.skippedUnchanged, eventsAppended: r.eventsAppended, changed: r.changed };
  },

  async relate({ from, to, type, attrs, kind, by, at }) {
    const r = await need().relate({ from, to, type, attrs, source: { kind, by, at } });
    return { id: r.id, from: r.from, to: r.to, type: r.type };
  },

  async assertFact({ about, predicate, value, confidence, kind, by, at }) {
    const f = await need().assertFact({ about, predicate, value, confidence, source: { kind, by, at } });
    return { id: f.id, supersededBy: f.supersededBy ?? null };
  },

  // Zeitreise: Zustand einer Entitaet zu einem fruehen Zeitpunkt, rekonstruiert durch Abspielen des
  // Ereignisprotokolls bis dahin (Engine-Funktion view("snapshot").entityAt).
  async entityAt({ id, at }) {
    const e = need().view("snapshot").entityAt(id, at);
    return e ? { id: e.id, type: e.type, name: e.name, state: e.state, attrs: e.attrs } : null;
  },

  // Die Referenz stellt beim Neustart jede Aussage aus dem Protokoll als Kopie wieder her; die Markierung "ueberholt"
  // (supersededBy) setzt sie nur im laufenden Speicher, nie im Protokoll - nach einem Neustart fehlt sie. Das Protokoll
  // ist aber vollstaendig. Darum werden die Fakten hier IMMER aus dem Protokoll neu abgeleitet: die gespeicherten
  // assertFact-Ereignisse laufen der Reihe nach durch die eigene Konfliktregel einer frischen Engine.
  // 'facts_live_consistent' sagt, ob der laufende Zustand ohnehin gestimmt hat (false = Markierungen waren verloren).
  async snapshot() {
    const m = need();
    const graph = m.view("graph");
    const entities = graph.query({});
    const live = new Map();
    for (const e of entities) for (const f of m.view("facts").about(e.id)) live.set(f.id, f.supersededBy ?? null);

    const scratch = new WorldModel({ namespace: "replay", storage: "memory", conflictPolicy: cfg.conflictPolicy, sourcePriority: cfg.sourcePriority });
    const assertions = m.events().filter((ev) => ev.kind === "assertFact").sort((a, b) => a.seq - b.seq);
    for (const ev of assertions) {
      const f = ev.payload;
      await scratch.assertFact({ about: f.about, predicate: f.predicate, value: f.value, confidence: f.confidence, source: f.source });
    }
    const sFacts = scratch.view("facts");
    const rebuilt = scratch.view("graph").query({}).flatMap((e) => sFacts.about(e.id).map((f) => ({
      id: f.id, about: f.about, predicate: f.predicate, value: f.value, confidence: f.confidence,
      source_kind: f.source.kind, source_by: f.source.by ?? null, asserted_at: f.assertedAt,
      superseded_by: f.supersededBy ?? null,
    })));
    const consistent = rebuilt.length === live.size && rebuilt.every((f) => live.get(f.id) === f.superseded_by);

    return {
      entities: entities.map((e) => ({ id: e.id, type: e.type, name: e.name, state: e.state, attrs: e.attrs })),
      facts: rebuilt,
      facts_live_consistent: consistent,
      relationships: m.events().filter((ev) => ev.kind === "relate").map((ev) => ({
        id: ev.payload.id, from: ev.payload.from, to: ev.payload.to, type: ev.payload.type,
        attrs: ev.payload.attrs ?? {},
      })),
      audit: m.audit().map((a) => ({ seq: a.seq, kind: a.kind, actor: a.actor, summary: a.summary })),
      event_count: m.events().length,
      events: m.events().map((ev) => ({ seq: ev.seq, kind: ev.kind, at: ev.at, payload: ev.payload })),
    };
  },
};

// Strikt nacheinander: jede Zeile wird erst fertig bearbeitet, bevor die naechste beginnt - sonst koennen
// Lese-Befehle vor den Schreib-Befehlen laufen, die vor ihnen gesendet wurden.
async function handleLine(line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch (e) {
    process.stdout.write(JSON.stringify({ id: null, ok: false, error: "ungueltiges JSON" }) + "\n");
    return;
  }
  const handler = handlers[msg.cmd];
  if (!handler) {
    process.stdout.write(JSON.stringify({ id: msg.id, ok: false, error: `unbekannter Befehl: ${msg.cmd}` }) + "\n");
    return;
  }
  try {
    const result = await handler(msg.args ?? {});
    process.stdout.write(JSON.stringify({ id: msg.id, ok: true, result }) + "\n");
  } catch (e) {
    process.stdout.write(JSON.stringify({ id: msg.id, ok: false, error: String(e && e.message ? e.message : e) }) + "\n");
  }
}

let chain = Promise.resolve();
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => { chain = chain.then(() => handleLine(line)); });
rl.on("close", () => { chain.then(() => process.exit(0)); });
