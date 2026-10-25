"""Sprechtexte und Zuordnung der Bilder - von make_video.py und make_voices.py gemeinsam genutzt.
Hier aendern, wenn sich ein Text aendern soll.

Der Ablauf folgt den 13 Folien (Foliensammlung.pptx): Problem -> Triage -> Bericht mit Ablehnungsschleife ->
'was wuerde es loesen' -> Zeitverlauf -> Meterless -> Messung -> [Zetaris] -> Grenzen -> Schluss.

visual = (art, name): "card" = Titelkarte, "term" = Terminal aus ECHTEM Lauf von main.py (siehe make_video.py).
placeholder=True marks a gap still to be filled (currently none)."""

SEGMENTS = [
    dict(id="00_hook", visual=("term", "hook"),
         text="The vendor says: safe by default. Your own ticket says: two of four clusters are "
              "unconfirmed. Who is right? Watch. The first draft says resolved. A second agent "
              "checks the evidence, and rejects it. The answer is unresolved, with the reason."),
    dict(id="02_problem", visual=("card", "02_equifax"),
         text="That gap is how Equifax lost data on about 147 million people in 2017. The fix for the "
              "Apache Struts flaw had been public for months. One system stayed unpatched, and nobody "
              "had checked it."),
    dict(id="01_opening", visual=("card", "01_opening"),
         text="This is the Vulnerability Conflict Resolver, built for the Open Agent Hackathon, in the "
              "track The Agent That Can Explain Why. Four agents, three sources, one rule: nothing is "
              "resolved until your own evidence says so."),
    dict(id="03_triage", visual=("term", "triage"),
         text="Four agents read all three sources for every case, and rank them. Real run, fourteen cases. Every row says what was decided, and why."),
    dict(id="04_log4shell", visual=("term", "log4shell"),
         text="Here is that Log4Shell case in full, with a simulated internal ticket. The vendor says the dangerous feature "
              "is off by default, so the Reconciler first marks it resolved. The Challenge Agent checks "
              "the internal ticket: two of four clusters are unconfirmed. It rejects the draft. "
              "The revised answer is unresolved, and flagged for a human."),
    dict(id="05_next_steps", visual=("term", "next_steps"),
         text="And the report does not stop at no. It lists what would resolve the case."),
    dict(id="06_timeline", visual=("term", "timeline"),
         text="Evidence arrives over days. Here is the Struts case, simulated. On day four, thirteen of "
              "fourteen applications are confirmed, and the dispute portal is not. The system stays "
              "unresolved. Only on day nine, when that portal is upgraded and re-tested, does it say "
              "resolved. That is the Equifax gap, caught."),
    dict(id="07_meterless", visual=("term", "meterless"),
         text="Underneath runs the real Meterless World Model, the unmodified open source engine, "
              "through a small Node bridge. Every belief carries its source, a conflict policy decides "
              "internal evidence beats the database beats the vendor, and a time-travel check confirms "
              "each source only existed from its first day. "
              "Without Node, a Python port takes over."),
    dict(id="08_zetaris", visual=("term", "zetaris"),
         text="The data layer is Zetaris. In this real run the sources come from a SQL view over three REST tables, "
              "and the report shows the query. A second query reads the exploitation signal. Heartbleed is known "
              "to be exploited, so it ranks higher, but the verdict stays unresolved."),
    dict(id="09_measure", visual=("card", "09_measure"),
         text="We measured the certainty check on our own corpus of two hundred eighty-six sentences, "
              "using only the half we never tuned on. Rules alone miss almost every hedge. A model with "
              "our first prompt raised fifty false alarms. The second prompt cut them to ten, at three misses in fifty-six. A third prompt was worse, so we did not adopt it. Nemotron 3.5 lightning, through NVIDIA's API, met our "
              "pre-set bar twice on our corpus. On twenty-four real advisory sentences it was too cautious."),
    dict(id="10_limits", visual=("card", "10_limits"),
         text="Honest limits. Zetaris, Nemotron and a Meterless Runtime provider, which only ran against a stand-in. "
              "Tickets and timelines are simulated. The corpus is "
              "our own. There are no users yet. "
              "And if a vendor never answers, this system can never say resolved. That is deliberate."),
    dict(id="11_closing", visual=("card", "07_closing"),
         text="The Vulnerability Conflict Resolver. Track: The Agent That Can Explain Why. "
              "Sponsor tech: Meterless, Zetaris and NVIDIA. The code is on GitHub."),
]
