# Evidence directory

Drop evidence files here on the host (CloudTrail JSON exports, pcap-derived text
from `tshark`/`tcpdump`, log excerpts, analyst notes, etc.). This directory is
bind-mounted read-only into the `runner` container at `/var/casky/evidence`
(see `docker-compose.yml`), so anything you save here is immediately visible
inside the container at the same relative path — no `docker cp` needed.

Then generate a plan directly from a file instead of the interactive paste
prompt:

```bash
docker exec -it casky-runner casky harness -i /var/casky/evidence/cloudtrail-export.json
```

**Use the in-container path, not a host path.** `-i` runs inside the `runner`
container, which has its own isolated filesystem — a host path like
`~/Downloads/...` will never resolve there. Copy the file into this directory
first, then pass `/var/casky/evidence/<filename>`.

**50,000-character limit.** Evidence text is embedded verbatim into every LLM
prompt in the classifier pipeline, so a large, unfiltered file (a full pcap, a
multi-MB log dump) would blow past any provider's context window — `-i` rejects
anything over the limit before even reading it. Pre-process large files first:
extract only the relevant lines/events (`jq` for JSON, `tshark`/`grep`/`awk` for
pcap-derived text) rather than passing the full raw capture. A compact summary
(what was scanned, by whom, over what window) is both smaller and better
evidence than a raw dump.

`casky harness -i` doesn't accept literal `.pcap` files — for packet captures,
run `tshark -r yourfile.pcap -nn` (or `tcpdump -r yourfile.pcap -nn`) yourself
first and save the *text output* (filtered/summarized, per above) here instead.

Everything in this directory except this file is gitignored — evidence can
contain real, sensitive investigation data and must never be committed.
