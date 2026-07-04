# Lane Router

A reference implementation of the **Two-Lane Rule**: *sensitive data takes the local
lane, always.*

Every AI request passes through one auditable question — would this data need a BAA? —
and gets routed accordingly. Requests that trip sensitivity detectors run on **local
models** (Ollama, on your machine, nothing transmitted). Clean requests may use the
**cloud lane** and the best frontier model you configure. Every decision is written to
an audit log that stores **metadata only, never the text**.

Built for small regulated operators — healthcare practices, law offices, accounting
firms — where staff are already pasting sensitive material into consumer AI tools and
enterprise procurement is never going to arrive in time.

## Quickstart (the real router, ~2 minutes)

Requires Python 3 and [Ollama](https://ollama.com) with at least one model pulled:

```
ollama pull qwen2.5:14b
git clone https://github.com/rcoxjrd/lane-router && cd lane-router
python3 server.py
```

Open http://127.0.0.1:8788 — paste text, watch it route, read the audit trail.

**Cloud lane** is disabled until you deliberately enable it:

```
CLOUD_CMD="claude -p" python3 server.py     # or any CLI that takes a prompt as its final arg
```

**Known-name detection:** add a `names.txt` (one name per line, e.g. your client roster)
and those names become detector hits and get redacted in previews. This file is
gitignored; it never leaves your machine.

## The demo you may have arrived from

The hosted page is a **simulation** — same detectors running in your browser, canned
responses, nothing executed. Static hosting cannot run a local lane; that is rather
the point. Clone and run locally for the real thing.

## How routing works

1. Deterministic detectors (regex) scan for SSNs, phones, emails, DOBs, MRN/member IDs,
   name labels, addresses, diagnosis codes, sensitive keywords, and roster names.
2. Any hit → **local lane** (Ollama). No hits → **cloud lane** (if configured).
3. Detectors are conservative on purpose: false positives route local, which is the
   safe direction. There is no override that sends a detector hit to the cloud.
4. The audit entry records timestamp, content hash, character count, lane, reasons,
   model, and latency. The raw text is never logged.

## What this is not

- **Not HIPAA compliance.** Compliance is an organizational program; this gives the
  program a rule it can check in an afternoon.
- **Not an air gap.** On-device inference means the data doesn't leave; the wire isn't
  cut. (Turn off the network and the local lane keeps working.)
- **Not perfect detection.** Regex catches structure, not meaning. Treat the detector
  list as a floor and extend it for your domain. PRs welcome.

## Files

```
server.py     the router: detectors, lanes, audit log, API, serves the GUI
index.html    the GUI; auto-switches to demo simulation when no backend answers
names.txt     optional, gitignored: your roster of names to detect and redact
lane_log.jsonl  the audit trail (gitignored; metadata only)
```

## Deploying the demo page

The static `index.html` deploys anywhere (Vercel, GitHub Pages). It self-detects the
missing backend and shows the labeled simulation. `vercel.json` is included.

## License & author

MIT. Built by [Ryan Cox](https://coxcontent.com), who runs this exact stack daily in a
behavioral health consulting practice. The white paper behind it is on the site. Issues
and PRs welcome, especially detector patterns from other regulated domains.
