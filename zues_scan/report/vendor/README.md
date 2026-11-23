# Vendored third-party code

The HTML report is one file that opens offline, so the libraries it needs are copied
here and inlined into every report. Nothing in this folder is ever loaded from the
network, by ZuesScan or by a report.

| File | What | Version | License | SHA-256 |
|---|---|---|---|---|
| `cytoscape.min.js` | [Cytoscape.js](https://js.cytoscape.org/) — graph rendering | 3.34.4 | MIT (`cytoscape.LICENSE.txt`) | `081591ab735b2b6a3b31a3c60f8f3a3e2fee8c92939e0c7820ad1208571b6cd8` |

## Where it came from

`dist/cytoscape.min.js` and `LICENSE` from the npm package `cytoscape@3.34.4`
(`https://registry.npmjs.org/cytoscape/-/cytoscape-3.34.4.tgz`). The tarball was checked
against the registry's `dist.integrity` (sha512) before extracting.

`tests/test_report.py` checks that the file still matches the SHA-256 above, so a
modified copy cannot slip in unnoticed.

## Upgrading

1. Pick a release that is at least two weeks old.
2. Download the tarball, verify `dist.integrity`, extract the two files.
3. Update the version and SHA-256 here and in `tests/test_report.py`.
4. Generate a report and open it with the browser console open: the page's Content
   Security Policy only lets scripts and styles with a known hash run, so a library that
   starts injecting its own `<style>` or calling `eval` shows up as a CSP violation.
