# Nmap command workbook
Open index.html in a browser. All styling, scripts and option metadata are embedded; no installation, network access or Nmap binary is required. Type or paste a command, inspect the explanation and breakdown, or expand **Build with controls** to search options and append targets. Remove individual flags, targets or shell text directly in the breakdown. File-list contents are optional and remain in memory. Nothing executes.

The current command is kept in the URL hash (`#cmd=…`), so a reload keeps it and the URL can be shared. List contents are never written to the URL.

Edit catalog.txt (group headers; @ marks required values, ? an optional attached value), core.js (tokenization, parsing, value and conflict checks, IPv4 scope math), view.html (markup/styles), and ui.js. Run `python3 build.py` to regenerate index.html and `node test.cjs` to run the test suite (see REQUIREMENTS.md). coverage.txt records the audited Nmap release and argument types; `tools/extract-inventory.py` rebuilds it from Nmap source. No runtime or package dependencies.

Scope is the number of distinct IPv4 addresses, not an estimate of packets or elapsed time. IPv4 addresses, octet ranges and wildcards (`10.0.0.1-50`, `10.0.*.1`) and CIDRs are counted; hostnames and IPv6 stay symbolic. No DNS or shell expansion, filesystem reads from command tokens, privilege checks or per-script argument validation. Shell syntax (`;`, `|`, `&&`, redirects, `$(…)`, backticks, `#` comments) ends the Nmap command and is shown as shell text with a warning; `$VARIABLES` stay literal with a warning; `<placeholders>` are noted as values to fill in. The builder handles exact named forms, selected aliases, quoted values, long equals syntax, attached short arguments and combined scan selectors; it is not a shell or a full getopt implementation.

## Checked values
Values are validated only for these flags (bounds from Nmap 7.993); other values are recognized but not checked:

- Timing template: `-T`, `--timing` (0–5 or paranoid … insane)
- Ports: `-p`, `--exclude-ports` (ports 0–65535, ranges, service names, T:/U:/S:/P: prefixes)
- Port selection: `--top-ports` (1–65535), `--port-ratio` (0 to below 1)
- Version detection: `--version-intensity` (0–9)
- Retries and rates: `--max-retries` (whole number), `--min-rate`, `--max-rate` (positive number)
- Times: `--host-timeout`, `--scan-delay`, `--max-scan-delay`, `--min-rtt-timeout`, `--max-rtt-timeout` (≥ 5ms), `--initial-rtt-timeout` (≥ 1ms), `--script-timeout`, `--stats-every`
- Groups and parallelism: `--min-hostgroup`, `--max-hostgroup`, `--min-parallelism`, `--max-parallelism`, `-M` (≥ 1)
- OS detection: `--max-os-tries` (1–50)
- Packets: `--ttl` (0–255), `--mtu` (multiple of 8), `--data-length` (0–65400), `-g`, `--source-port` (0–65535)
- Targets: `-iR` (whole number)
- Verbosity: `-v`, `-d` (attached digits or repeated letters)
- Output: `-oA` (not `-`)

Common conflicts that Nmap rejects (for example several TCP scan types, `-sn` with port selection, duplicate outputs, `-6` with IPv4 targets) are reported as errors; see REQUIREMENTS.md R14.
