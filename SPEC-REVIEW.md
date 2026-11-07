# Adversarial spec review (2026-11-07)
Evidence: probes run against core.js. `node test.cjs` passes.

## Blockers: decide before agents start
B1. The spec isn't testable. SPEC.md is 5 prose paragraphs with no requirement IDs and no acceptance criteria. Phase goal "browser walkthrough" has no pass/fail definition, and there are 0 UI tests.
B2. Shell syntax is silently accepted. `nmap 10.0.0.1; rm -rf /` parses with `10.0.0.1;`, `rm`, `/` as targets and `-rf` as an unknown flag. `|`, `$(...)` and `&&` also give no warning. The spec says "never present unrecognized constructs as verified", but these are shown as targets.
B3. The inventory isn't reproducible. The spec requires "reproducible inventory against the upstream parser", but no extraction script exists. coverage.txt and catalog.txt are both hand-written, and test.cjs checks one against the other (circular). The pinned version "Nmap 7.993" and its SHA256 are unverified.

## Spec gaps: need a decision
G1. Shell dialect is undefined. The lexer follows POSIX sh quoting. Windows cmd and PowerShell quote differently. `nmap.exe`, `NMAP` and `/usr/bin/nmap` are rejected with "Start with nmap".
G2. Octet ranges aren't counted. `192.168.1.1-50` and `192.168.1.*` are core Nmap target syntax and countable, but they show "Scope retained as entered". IPv6 isn't counted either.
G3. Value validation is ad hoc. Only --max-rate, --min-rate and --max-retries are checked. `-T9`, `-p 99999` and `--top-ports abc` pass silently. The spec defers value domains, but the code already validates some. There's no rule for where the line is.
G4. Conflicts aren't caught. `-sS -sT` (Nmap errors on multiple TCP scan types), a duplicate `-oA`, and `-6` with an IPv4 target all pass. For `-6 10.0.0.1` the scope still says "1 distinct IPv4 address".
G5. Persistence and hosting are unspecified. ui.js contains leftover `window.openai` widget-state code, which is dead on GitHub Pages. A page refresh loses the command. Share-by-URL isn't defined.

## Minor
- `-iL -` (stdin) shows a "-" file-paste box. Spec intent is unclear.
- `$R/ot-find` is kept literal, which is correct per spec, but there's no beginner warning that a real shell would expand it.
- README has no GitHub Pages build or deploy steps. index.html is generated into the source folder.

## Decisions (Phil, 2026-11-07)
- Phase 1 goal: browser walkthrough plus fixes, driven by numbered, test-backed requirements.
- Delivery: one offline HTML file, optionally a simple GitHub Page. Reformatting is allowed ("building the real version").
- G1: POSIX shell quoting. Also accept `nmap.exe`, a path ending in `/nmap`, and case-insensitive `NMAP`. Warn on shell metacharacters (`; | & && || $( ) backticks > <`) and never treat them as targets (fixes B2).
- G2: count IPv4 octet ranges and wildcards (`1.2.3.1-50`, `10.0.*.1`). IPv6 stays symbolic.
- G3: validate values for common flags only (-T, -p, --top-ports, timing/rate numbers, --version-intensity, etc.). Document which flags are checked.
- G4: catch about 10 common conflicts (multiple TCP scan types, -4/-6 with a target of the other family, duplicate output flags, -sL with scans, ...).
- G5: remove the window.openai code. Persist the command in the URL hash so it's shareable.
- B3/Q11: write an extraction script that builds the flag inventory from real Nmap source (nmap.cc long_options plus short-option string), and confirm the pinned release and SHA256.
- Git: Phil does all commits and git actions. Agents never run git write commands.

## Phase 2 backlog (Phil, 2026-11-07). NOT in Phase 1 scope
- Saved command library: save typed or built commands with a name and tags; reopen, edit and copy them. Works offline (browser storage), with export/import as a JSON file for team sharing.
- Starter set: pre-load the commands in tests/fixtures/ccsf-examples.json (kinds valid and placeholder; leave out broken ones or label them clearly), browsable by category. Keep the source file:line attribution.
- Phase 1 work must not block this: keep the parse/explain API callable from a library view.

## Decisions round 2 (Phil, 2026-11-07)
- R4 newline: join unescaped line breaks into one command, with a warning that a real shell would run them as separate commands.
- Redirects (`>`, `>>`, `<`, `2>`, `&>`): skip the operator and its filename with a warning, then keep parsing. Only `;`, `|`, `&&`, `||` and `&` stop parsing. `<placeholder>` tokens are recognized before `<` is treated as a redirect.
- Gadfly's extras approved: # comments, Unicode-dash error, smart-quote warning, no-effect warnings, 18 conflict rules.
