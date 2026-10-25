# Outside review: what was found and what was done

Source: an **AI review** (the Claude model, asked to act as a vulnerability manager), supplied by the author. It ran and read the project. It is
**not** a human user, a user study or production use. (Claude also helped write this project, so this is a review by a model of the same family;
that is a limit of its independence.)
The review ran the rule-based mode on typical ticket texts. Its points, and the status of each:

| # | Point | Status |
|---|---|---|
| 1 | **False "resolved"** in rule mode: the ticket only had to contain "running/upgraded/installed" plus *any* version number. Four texts came out "resolved": "Running 2.14.1 on all hosts, upgrade pending approval", "upgraded the test VM to 2.17.1, production still runs 2.14", "installed 2.17.1 on prod, backup image still bundles 2.14", "patched web01 to 2.17.1" (one host of how many?). | **Reproduced and fixed.** `agents/reconciler.py: deployment_check` now takes the fixed versions from the vendor text, compares every version in the ticket (branch-aware, e.g. Spring 5.3.18 and 5.2.20), rejects pending/approval wording, rejects test/staging-only statements, and rejects a single named host without a stated scope. Regression tests: `check_fix_path.py` section C (22/22). |
| 2 | Wrong inputs: real findings come per asset from a scanner (Tenable, Qualys, Trivy ...), the proof is the rescan, and the unit is asset x CVE. | **Not done.** Stated as a limit. Three free-text sources per CVE remain the model. |
| 3 | Priority uses only CVSS; CISA KEV, EPSS, exposure and asset criticality are missing. | **Not done.** Stated as a limit. |
| 4 | Vendor side has a machine-readable standard (VEX/CSAF). | **Not done.** Stated as a limit. |
| 5 | Too much hackathon ballast for a job context. | Accepted; the juror quickstart and the README top are the short path. |
| 6 | Better use: check closed tickets, flag where the justification does not carry the closure. | Noted as the most useful direction; not built. |

Limits of the fix in point 1: it is still a set of rules, so unusual wording can slip through in either direction (the OpenSSH
case in `data/real_world/` is the known example in the safe direction). The "vendor says safe by default" path does not use version
comparison. The AI mode was not re-measured after this change.

## Second round (same day)

After the fix, the same AI reviewer wrote ten new ticket texts we had not seen. Result as reported by the reviewer: 7 of 10 correctly stayed
unresolved (including 2.17.0 instead of 2.17.1, "40 of 42", an old version still on disk, a wrong version branch, an outdated check) and real
confirmations ("verified with a rescan") were still recognised. Three slipped through on **wording**, not on the version logic:
"the legacy box was left out", "except the two SAP appliances", "no one verified it on the hosts".

Done: the three are regression tests (`check_fix_path.py`, now 25/25) and `deployment_check` rejects exclusion wording and "not verified" wording.
Deliberately **not** done: the shared uncertainty rules in `agents/source_mapper.py` were left untouched, so the dev/test split of the evaluation corpus stays valid.
We have the reviewer's ten new texts only as the reviewer's summary, not verbatim, so only the three named wordings are tests.

Wording the reviewer offered for the submission (an AI review, so it must be labelled as one): "An AI review (Claude, acting as a vulnerability manager) of the fixed
version: the version check now compares the running version against the vendor's fixed versions and rejects pending, test-only and single-host statements. All four original false
'resolved' cases and 7 of 10 new, unseen ticket texts were handled correctly; 3 still slipped through on exclusion or 'not verified' wording rather than on the version logic."

## Third round (same day) and a change of principle

Twelve fresh texts. Dangerous direction: 4 of 8 came out as a false "resolved" ("the DMZ jump host will follow", "the DR site still has to be done",
"I think the batch servers were included", "all prod web servers ... app and DB tier are owned by another team"). Harmless direction: 3 of 4 real confirmations
were wrongly blocked by words of the new exception list ("no host was skipped", "nothing other than log4j was changed", "could not find 2.14 anywhere").

The reviewer's diagnosis: every round fixes exactly the wordings that were named and the next wording slips through; that is the limit of regex on free text.
Recommendation, adopted: **turn the burden of proof around.** The fix path no longer tries to list more warning words; "resolved" now needs a **positive proof**:
a named verification method (scan, rescan, verified, confirmed by, tested, inventory, audit ...), a fixed version and a scope. None of the four slipped texts names a verification.
Price: "All prod hosts now run 2.17.2" without any proof stays open; for a security process that is the right side.

Also done: negated exceptions ("no host was skipped", "nothing other than ...") no longer count as exceptions in the fix path; an old version that is explicitly
gone ("could not find 2.14 anywhere") no longer blocks. `check_fix_path.py` is now 32/32.
Known and left as is: the shared uncertainty rules in `agents/source_mapper.py` still treat "skipped" and "could not find" as doubt words, so two of the real confirmations stay open
(safe direction, only costs alarm). They were not touched so that the dev/test split of the corpus stays valid; `check_fix_path.py` pins this behaviour.

Our reading: more rounds with the same reviewer would repeat the pattern. What would help next is a human practitioner or an anonymised real ticket export.
Rule-based checks on free text stay brittle against new wording; this is stated in the README and in the submission text.
