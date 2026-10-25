# Feedback from a real person (IT / Security) - template

Goal: an honest judgement from someone who evaluates such vulnerabilities professionally or privately. Don't fish for praise -
criticism is worth more. **Only record what the person actually said, and only with their consent.**

## Message to the person (adapt)

> Do you have 15 minutes? For a hackathon I built an agent that, for vulnerabilities, reconciles the statements from the database,
> the vendor and the internal ticket and says whether something is really "fixed" - and why (not). I'd like to know whether you, as a
> professional, find the report understandable and useful. Please be honest, including negative.

## Procedure (15 minutes)

1. You share your screen (or they run it themselves, quick start: `JUROR_QUICKSTART.md`):
   `python3 main.py --case CVE-2021-44228` and read the report together with the person.
2. Then the timeline: `python3 main.py --case CVE-2017-5638` (Struts, day 4 vs. day 9).
3. Only now the questions. Note the answers verbatim, **do not explain or defend**.

## Questions (ask verbatim)

1. After the report, do you understand **why** the system says "not resolved"? What was unclear?
2. Would you use the "WHAT WOULD RESOLVE THIS" list in everyday work? What is missing from it?
3. Which source or signal would you additionally need in practice (e.g. asset inventory, SIEM, ticketing system)?
4. Where would you **not** trust the system?
5. Would you try something like this if it were connected to your ticketing system? Why / why not?

## Note sheet (fill in)

- Role of the person (general, e.g. "Sysadmin", "Security Engineer"; name only with permission): ________
- Date: ________   Duration: ________
- Answers 1 to 5 (verbatim): ________
- Did the person find something that was actually wrong or misleading? ________ (-> treat as a bug in the project)
- May I use a short quote anonymously (or with the name) in README / video / slides?  ☐ yes, anonymous   ☐ yes, with name   ☐ no
- The exact quote that was approved: ________

## How it goes into the submission

- Only an approved, **verbatim** quote; never present a paraphrase as a quote.
- Honest sentence for README / limits slide, e.g.: "Reviewed informally by one IT professional (n=1): <quote>. This is not a user
  study." Only remove "No real users yet" once it is true - and even then n=1 remains a single case.
- Criticism that is valid belongs in the limits, not the trash.
