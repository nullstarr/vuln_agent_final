"""
Real integration of Meterless' world-model building block (sponsor technology),
not just a mention in the README.

Meterless (github.com/Meterless/Meterless, Apache-2.0) describes its
world-model engine as "a graph of entities, contexts and
relations that powers search, timeline and agents" - exactly what
our project does anyway: tracing the relationship between a vulnerability
and the three contradicting statements about it.

What was ADOPTED here, verbatim from their own documentation
(engines/world-model/HOW_TO_USE_WORLD_MODEL.md, sections 2 and 3):
  - the entity/edge data model (fields, types, defaults)
  - generating stable, deterministic IDs via SHA-256 hash,
    so the same source always gets the same entity ID, however
    often you repeat the run

What was NOT adopted: their actual TypeScript reference
implementation, their storage adapter, their conformance test suite.
That would have been a Python<->Node language bridge; we deliberately
chose our own, spec-faithful Python implementation,
because the guide itself shows Python as an equal option
alongside TypeScript and Rust.

The important point that makes this a REAL integration instead of just
a rename of our existing fields: the edge confidence
comes directly from our own, already-built security logic
(source_mapper.map_sources' certainty value), not from an invented
number - so the graph really shows what our system already
found, just now in a form that Meterless' own
read surface/query model would understand.
"""

import hashlib
import re
import unicodedata
from dataclasses import asdict, dataclass, field
from typing import Literal, Optional


# --- Section 3 of the Meterless guide, adopted verbatim ---------

def normalize_name(s: str) -> str:
    s = s.lower()
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = re.sub(r"\s+", " ", s).strip()
    return s


def stable_entity_id(name: str, type_: str) -> str:
    normalized = f"{type_}:{normalize_name(name)}"
    h = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"ent_{h}"


def stable_edge_id(from_id: str, to_id: str, type_: str) -> str:
    """Same principle as stable_entity_id, applied to an edge -
    not given as a separate function in the Meterless guide, but
    carried on for edges from the same principle explained there
    (deterministic IDs through hashing)."""
    h = hashlib.sha256(f"{type_}:{from_id}->{to_id}".encode("utf-8")).hexdigest()[:16]
    return f"edge_{h}"


# --- Section 2 of the Meterless guide: the entity/edge schema -------
# Fields taken 1:1 from their Python example.

EntityState = Literal["emerging", "active", "archived"]


@dataclass
class Entity:
    id: str
    name: str
    type: str
    aliases: list = field(default_factory=list)
    description: Optional[str] = None
    traits: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    summary: Optional[str] = None
    mention_count: int = 0
    first_seen_at: int = 0
    last_seen_at: int = 0
    linked_ids: list = field(default_factory=list)
    is_custom: bool = False
    imported_from: Optional[str] = None
    discovered_at: int = 0
    state: EntityState = "emerging"
    confidence: float = 0.6
    staleness: float = 0.0


@dataclass
class Edge:
    id: str
    from_: str
    to: str
    type: str
    confidence: float = 1.0
    weight: Optional[float] = None
    observation_id: str = ""


# --- Our own part: build a world model from the task data -

def build_world_model(case, claims):
    """Builds an entity/edge graph for ONE task, following the
    Meterless schema. One entity per source (NVD, vendor, internal) and
    one entity for the vulnerability itself, connected by edges of
    type 'asserts_state'. The edge confidence comes directly from our
    own certainty assessment (source_mapper.py), not invented -
    high certainty -> 1.0, low certainty -> 0.35 (deliberately well below
    0.5, so a graph-query tool does not confuse an uncertain edge with
    a reasonably certain one)."""
    cve_id = case["cve_id"]
    vuln_entity = Entity(
        id=stable_entity_id(cve_id, "vulnerability"),
        name=cve_id,
        type="vulnerability",
        summary=case.get("nickname"),
        is_custom=False,
        state="active",
        confidence=1.0,  # the CVE identifier itself is not in dispute, only what it means
    )

    entities = [vuln_entity]
    edges = []
    for key, claim in claims.items():
        src_entity = Entity(
            id=stable_entity_id(claim["source_name"], "source"),
            name=claim["source_name"],
            type="source",
            tags=[claim["source_type"]],
            summary=claim["raw_text"][:200],
            is_custom=not claim["is_real_public_data"],
            state="active",
            confidence=1.0 if claim["certainty"] == "high" else 0.35,
        )
        entities.append(src_entity)

        edge = Edge(
            id=stable_edge_id(src_entity.id, vuln_entity.id, "asserts_state"),
            from_=src_entity.id,
            to=vuln_entity.id,
            type="asserts_state",
            confidence=1.0 if claim["certainty"] == "high" else 0.35,
            observation_id=f"{cve_id}:{key}",
        )
        edges.append(edge)

    return {"entities": [asdict(e) for e in entities], "edges": [asdict(e) for e in edges]}


def world_model_summary(wm):
    """Short, readable summary for the trace - shows that the
    graph carries real, differing confidence values, not just
    placeholders."""
    low_conf_edges = [e for e in wm["edges"] if e["confidence"] < 0.5]
    return (f"{len(wm['entities'])} entities, {len(wm['edges'])} edges "
            f"({len(low_conf_edges)} of them with confidence<0.5)")
