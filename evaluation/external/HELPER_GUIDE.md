# Help me with a test - 10 minutes, no technical knowledge needed

I'm testing a program that recognizes whether a short IT-security text **really confirms something completely** or
**leaves doubt / gaps**. For the test to be fair, I need example sentences from **someone other than me**. That's you.

## What you write

About **20 sentences in English**, each a single sentence (or two), as if it were in a note from a software vendor
or in an internal ticket about a vulnerability. The question is: **Is a vulnerability fixed?**

- **10 sentences that confirm without doubt** (label `H`): everything is checked/fixed, nothing open.
  Example (invented): `H | We upgraded all 12 web servers to version 3.1 and verified each one with the scanner.`
- **10 sentences that contain some doubt or a gap** (label `L`): for example only part checked,
  still open, assumed, old, an exception, or an over-broad promise. Example (invented):
  `L | The upgrade should be complete, but we have not checked the two legacy servers yet.`

## Rules so it counts

1. **Write freely, in your own words.** Don't use my examples as a template and don't ask me what would be "right".
2. **You decide the label** (`H` or `L`), not me. If you're unsure, better write the sentence clearly.
3. **At least 25 characters per sentence**, no duplicates. Invented numbers and names are fine.
4. No real company, customer or personal data.

## Format

One text file (`.txt`), **one line per sentence**, exactly like this:

```
H | We replaced the vulnerable library on all 8 hosts and re-ran the full test suite; no failures.
L | Two of the five clusters are patched; the other three are scheduled for next month.
```

Send me the file. Thanks!
