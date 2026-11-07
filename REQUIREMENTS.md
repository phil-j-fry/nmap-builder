# Phase 1 requirements

Owner: Gadfly (spec and tests). Sources: SPEC.md, SPEC-REVIEW.md Decisions (authoritative), Phil's addendum on the CCSF corpus, and the Nmap 7.993 source (`nmap.cc`, `NmapOps.cc`, `scan_lists.cc`, `nbase/nbase_addrset.c`). Source lines are quoted where a rule mirrors Nmap behavior.

Every requirement has pass/fail acceptance criteria. Test files:

| File | Covers |
|---|---|
| `test.cjs` | entry point: legacy checks, then runs every `tests/*.test.cjs` |
| `tests/core.test.cjs` | R1–R15 (parser, scope, values, conflicts) |
| `tests/builder.test.cjs` | R16–R18 (quoting, round trips, removal) |
| `tests/hash.test.cjs` | R23 (pure hash helpers) |
| `tests/ui.test.cjs` | R19–R25 via `tests/dom-shim.cjs` (Node built-ins only) |
| `tests/corpus.test.cjs` | R26, data-driven from `tests/fixtures/*.json` |
| `tests/inventory.test.cjs` | R27 (`tools/extract-inventory.py` against a pinned fixture) |

Run `node test.cjs`. It must exit 0 and print no failing tests. R28 is a manual browser walkthrough.

---

## R1. Parse result contract

`parse(text, map)` returns an object with:

- `flags`: `[{key, val, def, start, end}]`, as today. Unknown flags have `def === undefined`.
- `targets`: `string[]` of target words in source order. Values only; shell text is never included.
- `items`: every parsed element in source order, each `{kind, start, end, text}`, where `text === input.slice(start, end)`. `kind` is one of `'flag'` (in the catalog), `'unknown'` (a dash word not in the catalog), `'target'` or `'shell'`. Flag items also carry `key` and `val`. Target items carry `placeholder: boolean`. The flags of a grouped token (`-sSU`) are separate items that share `start` and `end`. Shell items carry `stop: boolean` (R4): there can be several redirect items (`stop: false`) and at most one stopping item (`stop: true`), which is always last.
- `diagnostics`: `[{level, code, msg, ...}]`, where `level` is `'error'`, `'warn'` or `'note'`. Conflict diagnostics carry `rule`. Value and no-effect diagnostics carry `key`.
- `issues`: messages of error-level diagnostics, `warnings`: messages of warn-level, `notes`: messages of note-level (each a `string[]`).
- `placeholders`: distinct placeholder texts in source order, including the angle brackets.

Pass when:
- (a) Every field exists on every result, including for `''`.
- (b) Items are sorted by `start`.
- (c) Every item satisfies `text === input.slice(start, end)`.
- (d) `issues`, `warnings` and `notes` equal the messages of the diagnostics at each level, in order.
- (e) An empty or whitespace-only input produces zero diagnostics.

## R2. Program name (G1)

The first word, after an optional exact `sudo`, is accepted when its basename after the last `/` or `\`, compared case-insensitively, is `nmap` or `nmap.exe`.

- Accepted: `nmap`, `NMAP`, `Nmap`, `nmap.exe`, `NMAP.EXE`, `/usr/bin/nmap`, `./nmap`, `/opt/nmap-7.993/bin/nmap`, `'C:\Program Files (x86)\Nmap\nmap.exe'` (quoted), and `sudo nmap`.
- Rejected with error `program`: `nmapx`, `nmap2`, `/usr/bin/nmap-foo`, `notnmap`, `nmap.exe.bak`, `/usr/bin/`, `sudo` alone, `sudo -u root nmap`, `doas nmap`, `FOO=1 nmap`, `; nmap 10.0.0.1`, `"nmap "` (with a trailing space inside the quotes), and the en dash `–sS` as the first word.

Pass when each accepted form plus ` -sS 10.0.0.1` has no `program` diagnostic and parses `-sS` and the target, and each rejected form has exactly one `program` error.

## R3. Lexing edge cases

POSIX `sh` word rules stay in place, including single quotes, double quotes, backslash escapes and adjacent quoted segments joining into one word.

- `nmap -oX "a b" 'c d'x 10.0.0.1` gives the `-oX` value `a b` and the targets `c dx`, `10.0.0.1`.
- An unclosed quote gives error `unclosed-quote`. A trailing backslash gives error `trailing-escape`.
- A backslash-newline is a line continuation: `nmap -sS \⏎ 10.0.0.1` has zero diagnostics and one target.
- A word that starts with a Unicode dash (U+2010–U+2015 or U+2212) gives error `dash-lookalike` naming the word, and the word is not a target. Nmap rejects these: "Unparseable option (dash, not '-')".
- Unquoted typographic quotes (`“ ” ‘ ’`) give warning `smart-quote`. They remain literal characters, as `sh` treats them.
- (R3a, review 1) Only space, tab and newline separate words, as in `sh`. Any other unquoted Unicode space (U+00A0, U+1680, U+2000–U+200B, U+202F, U+205F, U+3000, U+FEFF) stays inside the word and gives error `unicode-space`, with a message naming the code point as `U+XXXX`. These usually come from copying commands off web pages. Inside quotes they are literal and give no error.
- (R3b, review 1) `getopt_long_only` accepts single-dash long options with `=`. `-oN=x` gives `-oN` with value `x`, and `-script=default` gives `--script` with value `default`.

## R4. Shell operators, redirects and line breaks (B2, G1; Decisions round 2)

**Stopping operators.** These unquoted, unescaped operators end the Nmap command: `;`, `|`, `||`, `|&`, `&`, `&&`, `(` and `)`.

- From the first stopping operator to the end of the input there is one `shell` item with `stop: true`. Nothing in it becomes a flag, a target or a flag value.
- Text attached before the operator in the same word stays a normal word. `10.0.0.1;` gives the target `10.0.0.1`.
- One warning `shell-operator` is emitted. Its message names the operator.
- `(` and `)` are not on Phil's list. They still stop parsing, because a subshell is not part of a single Nmap command.

**Redirects (skip and continue).** `>`, `>>`, `>|`, `<` (when not a placeholder, see R8), `<>`, `&>`, `>&` and `<&` do not stop parsing.

- Each redirect operator, together with an fd number directly before it (`2>`) and its filename word, is skipped as its own `shell` item with `stop: false`. Examples: `> log`, `>log`, `2>/dev/null`, `2>&1`, `> 'my log.txt'`.
- Parsing then continues, so `nmap -oN x > log 10.0.0.1` keeps the target `10.0.0.1`.
- A redirect never supplies a flag value: `nmap -oN > log 10.0.0.1` gives `missing-value`.
- A redirect with no filename is a `shell` item of the operator alone.
- (Review 2) A here-document `<<WORD` or `<<-WORD` (the delimiter may be quoted) is a stopping item: its body is input data, not arguments. It runs to the end of the input, with `stop: true`, under warning `shell-redirect`, whose message mentions "here-document". A here-string `<<< word` is an ordinary skipped redirect.
- (Review 2) A placeholder can be a redirect filename: `> <outfile>` is one redirect item, and the placeholder is still listed in `placeholders`.
- Each input with redirects gets warning `shell-redirect`, whose message says a shell would redirect input or output there.

**Line breaks.** An unescaped newline (or CRLF) with non-whitespace on both sides is joined as a space. It gives one warning `line-break` per input, with the message "line break treated as a space; a real shell would run separate commands". Leading and trailing newlines are plain whitespace. A quoted newline is literal. A backslash-newline is a continuation with no warning. A `#` comment ends at its line, and parsing continues on the next line.

Quoted or escaped operators are literal and give no warning: `'a;b'`, `"a|b"`, `a\;b`, `a\>b`.

Pass when:
- `nmap 10.0.0.1; rm -rf /` gives targets `['10.0.0.1']`, no `unknown` item for `-rf`, one `shell` item with text `; rm -rf /` and `stop: true`, a `shell-operator` warning and no errors. The same holds for every stopping operator.
- Each redirect example in `tests/core.test.cjs` R4r gives the listed targets, flags and `shell` item texts, the `shell-redirect` warning, no `shell-operator` warning and no errors.
- `nmap 10.0.0.1 2>&1 | tee x` gives `shell` items `2>&1` (`stop: false`) and `| tee x` (`stop: true`).
- `nmap -sS\n10.0.0.1` gives targets `['10.0.0.1']`, flags `['-sS']`, zero errors and one `line-break` warning.

## R5. Command substitution (B2)

`$(` and backticks begin command substitution when they are unquoted or inside double quotes. Inside single quotes they are literal.

- The whole word containing the substitution, and everything after it, is the `shell` item.
- Warning `shell-substitution` is emitted.
- `nmap 10.0.0.$(echo 1)` has no targets, so it also gets error `no-target`.
- `nmap -sS "$(cat t)"`, ``nmap `cat t` ``, and `nmap -sS "x`id`"` all warn and produce no target from the substitution.
- `nmap -sS '$(id)' 10.0.0.1` has no warning and targets `['$(id)', '10.0.0.1']`.

## R6. Variable expansion notice

An unquoted or double-quoted `$NAME` or `${NAME}` stays literal and gives warning `shell-variable` that names the variable. The text is not a substitution and does not stop parsing.

(R6a, review 1) The same `shell-variable` warning applies, naming the parameter (`$1`, `$@`) or the variable name (`HOST` for `${HOST:-x}`), to the special parameters `$0`–`$9`, `$@`, `$*`, `$#`, `$?`, `$$`, `$!` and `$-`, and to any `${…}` form, such as `${HOST:-x}` or `${#X}`. A `$` followed by nothing expandable (`a$`, a lone `$`) is literal. (R6b, Plumb review) An unquoted or double-quoted `${` with no closing `}` gives error `unclosed-expansion`, because the shell would fail or wait for more input.

Pass when the OT example `nmap -sT -n -p 102,502,2404,4840,20000,44818 --max-rate 10 --max-retries 1 -iL ot-ranges.txt --excludefile exclude.txt -oA $R/ot-find` still has 8 flags, zero errors and the `-oA` value `$R/ot-find`, and it has exactly one warning, `shell-variable` mentioning `$R`. `'$R/x'` gives no warning. `\$R` gives no warning.

## R7. Shell comments

An unquoted `#` at the start of a word begins a comment that runs to the end of its line. The comment is a `shell` item with warning `shell-comment`. It has `stop: true` when it runs to the end of the input. When more lines follow, they are joined (R4), so the comment is a `stop: false` item and parsing continues on the next line.

- In `nmap 10.0.0.1 #note` the targets are `['10.0.0.1']`.
- `#` inside a word is literal: `nmap host#1` gives the target `host#1` and no warning.

## R8. Placeholders (corpus addendum 1)

A placeholder is `<` immediately followed by content and then `>`. The content starts with a letter or `_`, does not end with a space, contains only `[A-Za-z0-9_ .:/,+-]`, and is 1–64 characters long. It may contain spaces, as in `<brittle ports>`, and it may sit inside a larger word, as in `full-<host>` or `<HMI_WEB_PORT>,5900`. Recognition works both unquoted and inside quotes. An unquoted placeholder is not a shell redirect, and its spaces do not split words.

- Each distinct placeholder gives one note `placeholder` whose message contains "fill this in" and the placeholder text.
- `placeholders` lists them.
- Target items containing a placeholder have `placeholder: true`.
- A placeholder target satisfies "has a target", so there is no `no-target` error.
- A flag value containing a placeholder skips value checks (R12) and gives no `bad-value`.
- Not placeholders: `< a.txt`, `<a.txt` (unclosed), `<1abc>` (starts with a digit), `<host >` (trailing space), and `<>`. The unquoted ones are shell operators (R4).

Pass when:
- `nmap -n -sC -sV <host> -oA svc --excludefile exclude.txt --exclude-ports <brittle ports>` has zero errors, `placeholders` equal to `['<host>', '<brittle ports>']`, targets `['<host>']`, and the `--exclude-ports` value `<brittle ports>`.
- `nmap -sT -Pn -p <HMI_WEB_PORT>,5900 --max-rate 10 <host>` has zero errors.
- `nmap --resume <name>.nmap` has zero errors.

## R9. Target sanity (corpus addendum 2)

- A target made only of digits and commas that contains at least one comma, or a target ending in `,`, gives error `bad-target`. Its message says it looks like part of a port list.
- A dotted target of four numeric octet specs that Nmap's IPv4 range parser rejects gives error `bad-target`. Examples: an octet over 255 (`10.0.0.999`), a reversed range (`10.0.0.50-1`), a prefix over 32 (`10.0.0.1/33`), and an empty octet (`10..0.1`).
- Hostnames, IPv6 literals and short or inet_aton forms (`10.1`) are not errors.

Pass when `nmap 1091,2222 10.0.0.1`, `nmap 10.0.0.1 80,` and each malformed IPv4 example above give a `bad-target` error, and `nmap example.com ::1 10.1` gives none.

## R10. IPv4 scope counting (G2)

`scope(p, files)` counts distinct IPv4 addresses over targets and lists minus exclusions without enumerating addresses. The supported syntax is the per-octet grammar of Nmap's `parse_ipv4_ranges`:

- Each octet is `*`, or a comma list of `N`, `N-M`, `-M` (from 0) or `N-` (to 255).
- An optional `/bits` (0–32) also applies to ranged forms, as in `apply_ipv4_netmask_bits`.

`--exclude` splits on commas first (`load_exclude_string`), so octet comma lists do not apply inside `--exclude`. Exclude-file and target-list entries are whitespace-separated, with `#` comments.

| Command | Expected count |
|---|---|
| `nmap 192.168.1.1-50` | 50 |
| `nmap 192.168.1.*` | 256 |
| `nmap 10.0.*.1` | 256 |
| `nmap 10.0.0.1,3,5` | 3 |
| `nmap 192.168.1.-5` | 6 |
| `nmap 192.168.1.250-` | 6 |
| `nmap 192.168.1-2.1-2` | 4 |
| `nmap 10.0.0.1-10 10.0.0.5-20` (overlap) | 20 |
| `nmap 10.0.0.1-10 --exclude 10.0.0.1-3,10.0.0.10` | 6 |
| `nmap 10.0.1-2.0/24` | 512 |
| `nmap 10.0.0.0/24 10.0.0.1-300` | `bad-target` error (300 > 255); scope `''` |
| `nmap '*.*.*.*'` | 4,294,967,296 |
| `nmap '*.*.*.1' --exclude 10.0.0.0/8` | 16,711,680 |
| `nmap 0-255.0-255.0-255.0-255 0.0.0.0/0` | 4,294,967,296 |

Pass when each count matches exactly. The format is `^<n with en-US separators> distinct IPv4 address(es)? in scope after exclusions \(before discovery\)\.$`. The last three rows must each finish in under 2000 ms. The legacy CIDR and exclusion tests in `test.cjs` must still pass.

## R11. Scope message precedence

`scope()` returns the first of these that applies:

1. `''` when there are any error diagnostics.
2. A message matching `/Random targets/` for `-iR`.
3. `/until placeholders are filled in/` when any target, or any `-iL`/`-i`/`--excludefile`/`--exclude` value, contains a placeholder.
4. `/unknown until the named lists are supplied/` when a named list has not been applied.
5. `/Scope retained as entered/` when any term is not countable IPv4: hostnames, IPv6, or applied list contents with hostnames.
6. The count.

Applied list contents behave as follows:

- An applied empty `--excludefile` list excludes nothing. `-iL a --excludefile b` with `a='10.0.0.0/30'` and `b=''` gives 4.
- A missing list gives the unknown message.
- An applied empty `-iL` list gives 0.
- CRLF line endings, blank lines and `#` comments in list contents are ignored.
- The same filename used for `-iL` and `--excludefile` uses the one content, giving 0.
- `-iL -` (standard input) is a list named `-`.

Warnings do not hide the count. `nmap 10.0.0.1 | grep x` gives `1 distinct IPv4 address in scope after exclusions (before discovery).`

## R12. Value checks for common flags (G3)

These are error `bad-value` with `key`, skipped when the value contains a placeholder. Bounds are from Nmap 7.993 source.

| Flag(s) | Valid | Invalid examples |
|---|---|---|
| `-T`, `--timing` | `0`–`5`, or `paranoid`, `sneaky`, `polite`, `normal`, `aggressive`, `insane` (case-insensitive) | `9`, `6`, `-1`, `4.5`, `fast`, `''` |
| `-p`, `--exclude-ports` | comma list. Optional `T:` `U:` `S:` `P:` prefixes. Items are `N`, `N-M`, `-M`, `N-`, `-` (all), lowercase service names with `*` and `?` (starting with `[a-z*?]`), and `[...]` groups. Ports 0–65535. | `99999`, `65536`, `100-1`, `80,,443`, `80,` (trailing), `HTTP`, `X:80`, `1-2-3`, `abc!`, `[80` |
| `--top-ports` | integer 1–65535 | `0`, `abc`, `-5`, `1.5`, `65536` |
| `--port-ratio` | decimal in [0, 1) | `1`, `1.5`, `-0.1`, `x` |
| `--version-intensity` | integer 0–9 | `10`, `-1`, `a` |
| `--max-retries` | whole number ≥ 0 | `-1`, `x`, `1.5` |
| `--min-rate`, `--max-rate` | finite number > 0 | `0`, `-5`, `abc`, `Infinity` |
| `--host-timeout`, `--scan-delay`, `--max-scan-delay`, `--min-rtt-timeout`, `--max-rtt-timeout`, `--initial-rtt-timeout`, `--script-timeout`, `--stats-every` | `^\d+(\.\d+)?(ms|s|m|h)?$` (time spec) | `abc`, `5x`, `-1s`, `''`, `1.2.3` |
| `--max-rtt-timeout` | additionally ≥ 5 ms | `4ms` |
| `--initial-rtt-timeout` | additionally ≥ 1 ms | `0` |
| `--min-hostgroup`, `--max-hostgroup`, `--min-parallelism`, `--max-parallelism`/`-M` | integer ≥ 1 | `0`, `x`, `1-p80` |
| `--max-os-tries` | integer 1–50 | `0`, `51` |
| `--ttl` | integer 0–255 | `256`, `-1` |
| `--mtu` | integer > 0 and a multiple of 8 | `0`, `12` |
| `--data-length` | integer 0–65400 | `-1`, `x` |
| `-iR` | whole number ≥ 0 | `-1`, `x` |
| `-g`, `--source-port` | integer 0–65535 | `70000`, `x` |
| `-v`, `-d` (attached) | digits only, or repeated letters handled by the catalog | `-vx`, `-dz` |
| `-oA` | not `-`. Nmap: "Cannot display multiple output types to stdout." | `-` |

(R12a, review 1) Nmap skips whitespace around port-list items (scan_lists.cc:337), so `-p "80, 443"` is valid. Time specs follow `strtod`, so `.5s` and `0.5` are valid, while `.` and `5.` are not.

Pass when every valid example parses with no `bad-value` and every invalid example gives exactly one `bad-value` whose `key` is the canonical flag. The existing rate and retry checks are folded in as `bad-value`.

## R13. Checked flags are documented

`core.js` exposes `CHECKED_FLAGS`, a `string[]` that holds exactly the keys checked by R12. README.md has a "Checked values" section that lists every key in `CHECKED_FLAGS`. The coverage text in the UI names that section or lists the keys.

Pass when the set of `CHECKED_FLAGS` equals the R12 table keys and every key appears in README.md.

## R14. Common conflicts (G4)

Each conflict is an error `conflict` with `rule` set:

| rule | Condition (source) | Example |
|---|---|---|
| `tcp-scan-types` | more than one distinct type among `-sA -b -sT -sF -sI -sM -sN -sS -sW -sX` (NmapOps.cc:468). Grouped tokens count. Repeating the same type does not. | `-sS -sT`, `-sST`, `-sA -sI zombie`. Not: `-sS -sS`, `-sSU` |
| `ipproto-alone` | `-sO` with any TCP, UDP or SCTP scan type (NmapOps.cc:425) | `-sO -sU` |
| `noportscan-with-scan` | `-sL` or `-sn`/`-sP` with any scan type (NmapOps.cc:429) | `-sn -sS`, `-sL -sU` |
| `ports-without-portscan` | `-p` or `-F` with `-sn`/`-sP`/`-sL` (nmap.cc:1601) | `-sn -p 80` |
| `os-without-portscan` | `-O` with `-sn`/`-sP` (NmapOps.cc:490) | `-sn -O` |
| `fast-and-ports` | `-F` with `-p` (nmap.cc:1604) | `-F -p 80` |
| `duplicate-ports` | `-p` given twice (nmap.cc:1279), and likewise `--exclude-ports` | `-p 80 -p 443` |
| `duplicate-ping-ports` | `-PS` twice, `-PA`/`-PB` together or twice, `-PU`, `-PY` or `-PO` twice | `-PS22 -PS80`, `-PA -PB` |
| `duplicate-output` | an output type requested twice. `-oN`=`-o`, `-oG`=`-oM`=`-m`, `-oX`, `-oS`; `-oA` overlaps `-oN`, `-oX` and `-oG` (nmap.cc:886–914) | `-oN a -o b`, `-oA x -oX y`, `-oG a -m b`. Not: `-oN a -oX b` |
| `duplicate-input` | `-iL`/`-i` given twice (nmap.cc:934) | `-iL a -i b` |
| `both-families` | `-4` and `-6` (nmap.cc:1030) | `-4 -6` |
| `ip-family` | `-6` with an IPv4 literal, range or CIDR target or `--exclude` term; `-4` with an IPv6 literal target | `-6 10.0.0.1`, `-4 ::1`, `-6 10.0.0.0/24` |
| `rate-order` | `--min-rate` > `--max-rate` (NmapOps.cc:526) | `--min-rate 100 --max-rate 10` |
| `parallelism-order` | `--min-parallelism` > `--max-parallelism`/`-M` (NmapOps.cc:522) | |
| `hostgroup-order` | `--min-hostgroup` > `--max-hostgroup` (NmapOps.cc:583) | |
| `resume-alone` | `--resume` with any other flag or target (nmap.cc:1021) | |
| `defeat-rst` | `--defeat-rst-ratelimit` without `-sS` or `--open` (NmapOps.cc:507) | `-sT --defeat-rst-ratelimit` |
| `defeat-icmp` | `--defeat-icmp-ratelimit` without `-sU` (NmapOps.cc:511) | |

Pass when each example gives exactly one `conflict` with that rule and no other conflict, each "Not:" example gives no conflict, `nmap -6 10.0.0.1` has scope `''`, and the existing `-4 -6` and `--resume` tests still pass (they now carry rules). An IPv6 literal target without `-6` gives warning `ipv6-needs-6`.

## R15. Options with no effect

Each of these gives warning `no-effect` with `key`:

- `--version-intensity`, `--version-light`, `--version-all`, `--version-trace` or `--allports` without `-sV`/`-sR`/`-A`.
- `--osscan-limit`, `--osscan-guess`/`--fuzzy` or `--max-os-tries` without `-O`/`-A`.
- `--script-args`, `--script-args-file`, `--script-trace` or `--script-timeout` without `--script`, `-sC` or `-A`.

Pass when `nmap --version-all 10.0.0.1` warns and `nmap -sV --version-all 10.0.0.1` and `nmap -A --osscan-guess 10.0.0.1` do not.

## R16. Builder quoting and round trips

`core.js` exposes:

- `quoteArg(v)`: returns `v` unchanged when it matches `^[A-Za-z0-9_./:,=+@%-]+$`. Otherwise it returns `v` single-quoted, with `'` written as `'\''`. `''` returns `''`.
- `buildOption(key, value, map)`, which follows these rules:
  - `none`: returns `key`.
  - `required`: returns `key + ' ' + quoteArg(v)`. When `v` starts with `-` and is not exactly `-`, it returns the attached form instead: short `key + quoteArg(v)`, long `key + '=' + quoteArg(v)`.
  - `attached`: returns `key` when `v` is empty. Otherwise short `key + quoteArg(v)` and long `key + '=' + quoteArg(v)`.

Pass when, for every required or attached catalog entry and every value in the R16 corpus (`80`, `my report.xml`, `it's`, `a;b`, `$R/x`, `` `id` ``, `$(id)`, `-100`, `-`, `"q"`, `a\b`, `tab\there`, `ünïcødé`, `<host>`, `*`, `#x`, `a b  c`), the following holds. `parse('nmap ' + buildOption(k, v) + ' 10.0.0.1')` yields the first flag key `k`, the value exactly `v`, no `shell-*` warnings and no `missing-value`, `empty-value` or `unexpected-value`. Skipped: values that would change the key, such as `-v` with `v`, documented in the test.

## R17. Builder appends safely (UI)

- Add option and Add target insert text before the stopping `shell` item (`stop: true`, including a trailing comment). Redirect items are kept where they are, and new text goes after them. The result is `head.trimEnd() + ' ' + fragment + ' ' + stopText`, or without the last part when there is no stopping item. For example, adding `-p 80` to `nmap 10.0.0.1 | grep x` gives `nmap 10.0.0.1 -p 80 | grep x`. When the command is empty or whitespace, they produce `nmap <fragment>`.
- `.builder-msg` (new) is cleared after a successful add.
- (Review 1) When the text before the shell item is empty, as in `; ls`, the result starts with `nmap `: `nmap -sS ; ls`.
- When the command has an unclosed quote, adding does not change the command and shows a message in `.builder-msg`.
- Add target splits its input on whitespace into separate targets, each `quoteArg`'d, except a placeholder like `<brittle ports>`, which stays one target.
- A target starting with `-` is rejected: the command is unchanged and `.builder-msg` explains why.
- Add option with a required value that is empty leaves the command unchanged and calls `reportValidity`.

## R18. Removal preserves raw text

`removeItem(text, p, index)` (pure, in core.js) returns new text, and the UI Remove button uses it.

- For a non-grouped item it deletes `text.slice(start, end)` and the whitespace run immediately before it. All other bytes are unchanged.
- For a grouped scan token it rewrites the token as `-s` plus the remaining letters in their original order.

| Input | Remove | Result |
|---|---|---|
| `nmap -sS -oX "my report.xml" 10.0.0.1` | `-sS` | `nmap -oX "my report.xml" 10.0.0.1` |
| same | `-oX` | `nmap -sS 10.0.0.1` |
| same | target | `nmap -sS -oX "my report.xml"` |
| `nmap  -sS   10.0.0.1` | `-sS` | `nmap   10.0.0.1` |
| `nmap -sSU 10.0.0.1` | `-sS` | `nmap -sU 10.0.0.1` |
| `nmap -sSUV 10.0.0.1` | `-sU` | `nmap -sSV 10.0.0.1` |
| `nmap --script=default,safe -p80 x` | `--script` | `nmap -p80 x` |
| `nmap -sL -iL s.txt \| grep -F x` | shell | `nmap -sL -iL s.txt` |
| `nmap -sS -- -weird` | target `-weird` | `nmap -sS --` |

Pass when each row is exact and re-parsing the result never shows the removed item.

(Plumb review) The whitespace run stripped before an item includes backslash-newline (and backslash-CRLF) continuations, so removal never leaves a stray `\`. Removing `-p 80` from `nmap -sS \⏎ -p 80 \⏎ 10.0.0.1` gives `nmap -sS \⏎ 10.0.0.1`, and removing the target from `nmap -sS \⏎ 10.0.0.1` gives `nmap -sS`. Removal must not introduce a `trailing-escape` error or an escaped-space target.

## R19. Breakdown in source order (UI)

`.breakdown` has one `.token` row per item group. Grouped flags get one row each. Each row has `data-kind` set to `flag`, `unknown`, `target` or `shell`, a `code` element showing the text, a description and a `button` labelled "Remove".

- Target rows exist, a change from today.
- Placeholder target rows have class `placeholder` and contain the text "fill this in".
- Unknown rows contain "Not in the pinned catalog".
- Shell rows contain "Shell syntax" and "not part of the Nmap command".

Pass when rows appear in source order for `nmap -sS <host> --made-up 10.0.0.1 | grep x`, with kinds `flag, target, unknown, target, shell`.

## R20. Keyboard

- Every interactive control is a native `button`, `input`, `select`, `textarea` or `summary`. No click handlers sit on `div` or `span`.
- Every Remove button has an `aria-label` of the form `Remove <text>`.
- Enter (keydown) in `.value` triggers Add option, and Enter in `.target` triggers Add target, each calling `preventDefault`.
- After a Remove activation, focus moves to the Remove button now at the same row index, else the previous row's, else `.cmd`.

(Plumb review) The search ranks results: exact key match first, then key-prefix matches, then description-only matches. Searching `-p` lists `-p` first.

## R21. Validation failures are visible (UI)

- `.problem` has `role="alert"` and shows all error messages. (Plumb review) It is not inside an `aria-live` region, so errors are not announced twice. `.prose` and `.scope` are inside one.
- `.warnings` (new) shows warnings and notes.
- When there is any error, `.scope` is empty and `.prose` starts with "Partial interpretation".
- When there are no diagnostics, `.problem` and `.warnings` are empty.

## R22. List handling (UI)

- `.filebox` shows one container `[data-list="<name>"]` per distinct list name from `-iL`, `-i` or `--excludefile`. Each container has a label naming the list, a `textarea` and a `button` whose text contains "Apply list".
- `-` is labelled with text containing "standard input".
- Names containing a placeholder get no box.
- Apply updates `.scope`. Editing after apply returns to the unknown state until applied again.
- List contents never appear in `location.hash`.

## R23. URL hash persistence (G5)

- `encodeHash(cmd)` returns `'#cmd=' + encodeURIComponent(cmd)`.
- `decodeHash(h)` accepts a value with or without a leading `#`. It finds the `cmd=` parameter among `&`-separated pairs and returns the decoded string. It returns `null` when the parameter is absent, the percent-encoding is malformed, or the decoded value is over 8000 characters. `#cmd=` returns `''`.
- On load, a non-null hash value replaces the default example.
- Each command change calls `history.replaceState` (not `pushState`) with the new hash within 300 ms.
- A `hashchange` event loads the new command.
- (Review 1) A command over 8000 characters is not written to the hash. `.warnings` then says it is too long to save in the link.
- Hash content reaches the page only through `.value` and `textContent`. `#cmd=<img src=x onerror=alert(1)>` renders literally.

## R24. Dead code and unsafe DOM

- No source file (`ui.js`, `core.js`, `view.html`, `index.html`) contains `window.openai`, `openai:`, `setWidgetState` or `widgetState`.
- No source file uses `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval(`, `new Function` or `fetch(`. The DOM shim also throws on these.
- `index.html` contains `core.js` and `ui.js` verbatim, so it is not stale.

## R25. Narrow widths

Static checks:

- `view.html` keeps a `@media (max-width: …)` rule.
- No fixed `width` or `min-width` is over 320px.
- `.token` keeps `overflow-wrap:anywhere`.
- (Plumb review) `.result`, `.filebox` and `.builder-msg` (or the `#scan-desk` root) also have `overflow-wrap:anywhere`, so long port lists in `.prose` don't cause sideways scroll at 320px.
- `textarea` is `width:100%`.

Manual check in R28 at 320px and 375px: no horizontal scroll, and every control is usable.

## R26. Real-command corpus (data-driven, addendum)

`tests/corpus.test.cjs` loads every `tests/fixtures/*.json` that has an `examples` array. Each example's `kind` gives default expectations, and an optional `expect` object overrides or extends them.

| kind | default |
|---|---|
| `valid` | zero errors and zero warnings |
| `placeholder` | zero errors, at least one `placeholder` note |
| `fragment` | errors exactly `['no-target']` |
| `broken` | at least one error |
| `pipeline` | zero errors, a `shell-operator` warning, and a `shell` item |

`expect` keys:

- `errors` / `warnings` / `notes`: exact sorted multiset of codes.
- `errorsInclude` / `warningsInclude`: subsets of codes that must appear.
- `flags`: exact keys in order.
- `targets`: exact list.
- `placeholders`: exact list.
- `scope`: regex source string.
- `rules`: exact sorted conflict rules.

Unknown `kind` or `expect` keys fail the test, so typos can't silently pass. Each example is its own named subtest (`src`). Adding an example needs only JSON.

Pass when every corpus example passes, including:

- `archive/ICS/Readme.md:9` errors include `bad-value` (for `--max-parallelism`) and `bad-target`.
- `RECON-GUIDE.md:114` has a shell item `| grep -Fw 'for 10.0.5.20'` and no target `grep`.
- The fragments give only `no-target`.

## R27. Reproducible inventory (B3)

`tools/extract-inventory.py` (Python 3 standard library only) does the following:

- `extract-inventory.py <nmap.cc>` prints the `coverage.txt` registration section: one `name arity` line per `long_options[]` literal entry, in source order, with arity `no`, `required` or `optional`. It then prints the getopt short-option string and the SHA256 of the file.
- `--fetch <version>` downloads `https://nmap.org/dist/nmap-<version>.tar.bz2`, checks its SHA256 against nmap.org's `sigs/…digest.txt`, and extracts `nmap.cc` into a temp directory. On network failure it exits non-zero with a clear message and never falls back to stored data.
- `--check` compares the extraction with `coverage.txt`'s list and hash and with `catalog.txt`, reporting long options missing from the catalog, catalog long forms absent upstream, short option letters missing, and arity mismatches. It exits non-zero on any difference.

Status, 2026-11-07: verified by Gadfly with network. The 7.993 tarball SHA256 is `270e55f04915bfcecb5db8feb959d4c5ba86a48c094520a4f1c07571e1c79c59`, which matches nmap.org's digest. `nmap.cc` is `28ce3381…2b35`, which matches coverage.txt. `long_options[]` has 100 literal entries. The short string is `46Ab:D:d::e:Ffg:hIi:M:m:nO::o:P::p:qRrS:s::T:Vv::`. `-q` is in the short string but missing from catalog.txt. It has no `case` in the 7.993 switch, so Nmap accepts it and silently ignores it. Gadfly added it to catalog.txt as "accepted, no effect", and `--check` now exits 0 against the real 7.993 tarball.

Pass when `tests/inventory.test.cjs` runs the script on a small fixture `nmap.cc` excerpt (`tests/fixtures/nmap-cc-excerpt.cc`) and gets the expected lines, and, when `NMAP_SRC` points at a real `nmap.cc` or tarball, `--check` exits 0. That part is skipped when `NMAP_SRC` is unset; no Nmap source is vendored, for licensing reasons.

## R28. Manual browser walkthrough (Plumb, after implementation)

Open `index.html` from disk in a current Chrome and Firefox and record pass or fail for each:

1. Builder: add `-sS`, `-p` with `80,443`, a target and `-oX` with `my report.xml`. The command reads back correctly, and Remove for each restores the text.
2. Keyboard only: Tab through every control, add an option and a target with Enter, remove a flag with Enter or Space, and focus stays sensible.
3. At 320px and 375px wide there is no horizontal scroll and the command stays prominent.
4. `-sSU`: remove each half.
5. The OT example: apply both lists (and an empty exclusion), and the count updates. The count disappears on edit.
6. Paste each B2 example. Shell text shows as shell, not as targets.
7. Reload with a `#cmd=` URL, and copy and share the URL.
8. Paste `#cmd=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E`: no alert appears.

---

## Open items for the manager

- R4 newline and redirect handling: resolved by Phil (SPEC-REVIEW.md, Decisions round 2), and the spec and tests are updated. `(` and `)` still stop parsing; this needs a decision only if Phil disagrees.
- R7 (`#` comments), R3 (`dash-lookalike` and `smart-quote`) and R15 (`no-effect`) go beyond the G-decisions but are cheap beginner protections.
- R14 lists 18 rules rather than "about 10". Each rule is a literal fatal in 7.993 source.
- `-q` was in the 7.993 getopt string but not in catalog.txt. Gadfly added it as "accepted, no effect". This makes 163 named forms; the legacy count message changes with it.

---

# Phase 2 requirements (R29–R36)

Scope: the SPEC-REVIEW.md "Phase 2 backlog", plus the deferred unitless-time check. Phase 1 requirements and tests stay in force; nothing in Phase 2 may change Phase 1 behavior. New test files:

| File | Covers |
|---|---|
| `tests/library.test.cjs` | R29, R31–R33, R35 (pure functions) |
| `tests/library-ui.test.cjs` | R30, R32, R34–R36 (UI, via `tests/dom-shim.cjs`) |

## R29. Unitless time above Nmap's limit

Nmap reads a unitless time as seconds. When that value is at or above a per-flag limit, it refuses with "Since April 2010, the default unit … is seconds" (`parse_tval_msecs`, nmap.cc:516). This is a `bad-value` whose message suggests the `ms` spelling (for example `Use "100ms"`).

| Flag | Unitless limit (seconds) |
|---|---|
| `--max-rtt-timeout`, `--min-rtt-timeout`, `--initial-rtt-timeout` | 50 |
| `--scan-delay`, `--max-scan-delay` | 100 |
| `--host-timeout` | 10000 |

The check applies to decimal unitless values too (`60.5` is 60.5 s), matching `tval2msecs` (R29a, review 1).

Pass when the following hold:
- `--max-rtt-timeout 100`, `--scan-delay 500` and `--host-timeout 10000` each give exactly one `bad-value` whose message contains `ms`.
- `--max-rtt-timeout 49`, `--max-rtt-timeout 100ms`, `--scan-delay 99`, `--host-timeout 9999` and `--host-timeout 30m` give none.
- `--script-timeout` and `--stats-every` have no limit (Nmap parses them with `tval2secs`), so `--script-timeout 100000` gives none.

## R30. Build and files

- Library code lives in a new `library.js`. It is pure functions with no DOM, apart from what R34 needs in `ui.js`.
- `build.py` concatenates `const CATALOG=…`, `const STARTER_DATA=<contents of tests/fixtures/ccsf-examples.json>`, `core.js`, `library.js` and `ui.js`, in that order, into one offline `index.html`.
- There are still no runtime dependencies and no network requests. The only link out is a plain `<a href>` to the source repository.
- Every Phase 1 test passes unchanged.

Pass when `index.html` contains `library.js` verbatim and the fixture's `"commit"` value, and the full suite passes.

## R31. Library data model (`library.js`)

Constants:
- `LIBRARY_KEY = 'nmap-builder.library.v1'`
- `LIBRARY_FORMAT = 'nmap-builder-library'`
- `LIBRARY_VERSION = 1`
- `LIBRARY_LIMITS = {name: 100, cmd: 8000, tag: 32, tags: 10, entries: 1000, importBytes: 32000000}`. (Plumb review: raised from 1,000,000, so a normal full export of about 8.1M characters re-imports. The UI checks `file.size` in bytes, and the text check counts characters, which never exceed the UTF-8 byte count. Export measures the Blob size and, if it is over `importBytes` (possible only with heavily escaped content), still downloads, with a `.lib-msg` warning that the file is over the import limit.)

An entry is `{id, name, cmd, tags, source, created, updated}`:
- `id` is a non-empty string.
- `name` is trimmed, 1–100 characters.
- `cmd` is a string of up to 8000 characters with non-whitespace content, stored exactly as typed (not trimmed).
- `tags` is an array (see `normalizeTags` below).
- `source` is `null` or a string, for example `ccsf:archive/AD/README.md:27`.
- `created` and `updated` are ISO-8601 strings.

Functions:
- `normalizeTags(x)`: `x` is a comma-separated string or an array. Each tag is trimmed, lowercased, with inner whitespace runs replaced by `-`. A tag is kept only if it matches `^[a-z0-9][a-z0-9_.-]{0,31}$`. Tags are deduplicated in first-seen order, and at most 10 are kept. Example: `'AD, ot ics, OT-ICS, , x!'` gives `['ad', 'ot-ics']`.
- `makeEntry({name, cmd, tags, source}, {now, id})`: returns `{ok: true, entry}` or `{ok: false, error}`, where `error` names the field (`'name'` or `'cmd'`). `now` is epoch milliseconds, and `created = updated = new Date(now).toISOString()`. Without `id`, a unique id is generated: 1000 calls give 1000 distinct ids.
- `updateEntry(entry, changes, now)`: returns `{ok, entry}` with the same `id` and `created` and a new `updated`, validated like `makeEntry`. The input entry is not mutated.
- `searchLibrary(entries, {query, tag})`: query terms are whitespace-separated. Every term must be a case-insensitive substring of name, cmd, tags or source. When `tag` is set it must be one of the entry's tags. Results are sorted by `updated`, newest first, then by name.
- `allTags(entries)`: sorted, distinct tags.

(R31a, review 1) Stored and imported entries are made consistent: ids must match `^[A-Za-z0-9:._-]{1,64}$` and are unique within a library. The first occurrence keeps its id, and later duplicates or invalid ids get a generated id. A `source` longer than 300 characters becomes `null`.

## R32. Storage resilience

- `readLibrary(storage)` returns `{entries, status, dropped}`, with `status` one of `'ok'`, `'empty'`, `'unavailable'` or `'corrupt'`. It never throws.
  - `'unavailable'`: `storage` is null, or accessing it throws.
  - `'empty'`: the key is absent.
  - `'corrupt'`: the stored value is not JSON or not a library document. Then `entries` is `[]`, and the raw value is first copied to `LIBRARY_KEY + '.backup'` (best effort).
  - Individually invalid entries are dropped and counted in `dropped`; the status stays `'ok'`.
- `writeLibrary(storage, entries)` stores the export document (R33) under `LIBRARY_KEY` and returns `true`. It returns `false`, never throwing, when storage is unavailable or full.
- UI behavior:
  - Storage that throws on access, or on `setItem` (quota), must not break page boot or any Phase 1 behavior.
  - The library then works in memory for the session, and `.lib-msg` says that browser storage is unavailable and suggests Export.
  - A corrupt stored library is never overwritten before the backup exists, and `.lib-msg` says the saved library could not be read.
  - A `storage` event for `LIBRARY_KEY` (another tab) reloads and re-renders the list.

(R32a, review 1) `readLibrary` also returns `backupKey`: the key under which the raw corrupt value is verified stored (read back equal), or `null`. An existing backup with different content is never overwritten. Use `.backup`, else the first free `.backup-2` … `.backup-10`. If the same raw value is already backed up, reuse that key. The UI allows saving over a corrupt library only when `backupKey` is non-null, and `.lib-msg` names the key.

## R33. Export and import

- `exportLibrary(entries, now)` returns pretty JSON (2-space indent) `{format: LIBRARY_FORMAT, version: 1, exported: <ISO>, entries: [...]}` with only the R31 fields.
- `parseLibraryFile(text)` returns `{ok, entries, errors, dropped}`. It rejects, with `ok: false` and a readable `errors[0]`, in these cases:
  - text longer than `importBytes`;
  - invalid JSON;
  - a non-object, or a `format` mismatch;
  - a `version` that is not 1 (an integer above 1 says the file is from a newer version);
  - `entries` that is not an array, or has more than 1000 items.

  It never evaluates content. Unknown fields are ignored, and invalid entries are dropped and counted. A valid `created`/`updated` is kept, otherwise it is replaced by now. `__proto__` or `constructor` keys in the file must not pollute `Object.prototype`.
- (R33a, review 1) The UI checks `file.size > importBytes` before reading the file, so a huge file is never loaded into memory.
- `mergeLibrary(existing, incoming, now)` returns `{entries, added, skipped}`.
  - An incoming entry whose name, cmd and sorted tags equal an existing entry's is skipped.
  - Every other entry is added. Its id is regenerated if it collides with an existing id.
  - Existing entries are never modified.
- UI:
  - `.lib-export` downloads `nmap-library-YYYY-MM-DD.json` through a Blob and an `<a download>`.
  - `.lib-import` (an `<input type="file" accept=".json,application/json">`) reads the file as text, validates, merges, saves, and reports "Imported N … skipped M … D invalid" in `.lib-msg`.
  - An invalid file leaves the library unchanged and shows the reason.
  - Imported text renders only through `textContent`.

(Plumb review, data loss) The 1000-entry cap applies to every write path and never to reading your own storage.
- `readLibrary` accepts a stored library of any length.
- `mergeLibrary` adds only up to 1000 total and returns `{entries, added, skipped, rejected}`.
- Save (new entry) and Copy to my library refuse at 1000 with a `.lib-msg` saying the library is full. Editing an existing entry is still allowed.
- Import reports "N not added: library full".

## R34. Library UI

A `details.library` panel ("Saved commands") contains `.lib-name`, `.lib-tags`, `.lib-save`, `.lib-new`, `.lib-search`, `.lib-tag` (a select: "All tags" plus `allTags`), `.lib-list`, `.lib-export`, `.lib-import` and `.lib-msg` (`role="status"`).

- **Save.** `.lib-save` saves the current `.cmd` text with the name and tags.
  - A missing name calls `reportValidity` on `.lib-name` and saves nothing. An empty or whitespace command saves nothing and explains why in `.lib-msg`.
  - Commands with parse errors may be saved.
  - Saving persists via `writeLibrary`.
- **Rows.** Each entry is a `.lib-entry[data-id]` row containing `.lib-entry-name`, a `code` with the command, `.lib-entry-tags`, `.lib-status`, and the buttons `.lib-open`, `.lib-copy` and `.lib-delete`.
  - `.lib-status` uses the Phase 1 parser: "Parses cleanly", "N problem(s)" (errors), or "Fill in placeholders" (notes and no errors).
  - Rows appear in `searchLibrary` order, filtered live by `.lib-search` and `.lib-tag`.
- **Open and edit.** `.lib-open` loads the command into `.cmd` through the normal change path (explanation, breakdown and hash all update). It fills `.lib-name` and `.lib-tags` and makes that entry the one being edited.
  - A following `.lib-save` updates that entry: same id, new `updated`, no new row.
  - `.lib-new` clears the fields and the editing state, so the next save creates a new entry.
- **Copy.** `.lib-copy` writes the command to `navigator.clipboard.writeText`. If that is missing or rejects, `.lib-msg` says to copy manually.
- **Delete.** `.lib-delete` takes two clicks. The first turns the button into "Confirm delete"; the second, on the same button, deletes and saves. Any re-render cancels the pending confirm. `window.confirm` is not used. Deleting the entry being edited clears the editing state.
- (Plumb review) `.lib-editing`, next to Save, shows `Editing: <name>` while an entry is being edited and is empty otherwise. A `hashchange` that loads a new command ends the editing state (indicator and "Editing …" message cleared), so Save then creates a new entry. New clears it too.
- (Plumb review) Copy to my library checks `makeEntry`'s result. An invalid starter entry, such as a fixture title over 100 characters, shows a message instead of throwing.
- Every button is a native `<button type="button">` with an `aria-label` that includes the entry name.

## R35. CCSF starter set

- `starterEntries(STARTER_DATA)` returns read-only entries for examples whose `kind` is `valid` or `placeholder` (63 in the current fixture). `broken`, `fragment` and `pipeline` examples are excluded.
- Each entry is `{id: 'ccsf:' + src, name: title || src, cmd, src, category: category || 'Other', kind, tags: normalizeTags(['ccsf', slug(category || 'other')]), source: 'ccsf:' + src, readOnly: true}`. Ids are unique.
- `slug` lowercases the category, replaces runs of characters outside `[a-z0-9_.]` with `-`, and trims `-` from the ends. `'OT / ICS'` becomes `ot-ics`. This was clarified in review: plain `normalizeTags` would drop it.
- `starterOrigin(STARTER_DATA)` returns `{repo: source, commit}`.
- UI: a `details.starter` panel ("CCSF starter commands") shows the origin repository and the short commit as text. It contains `.starter-category` (a select: "All categories" plus distinct categories, sorted) and `.starter-list` with `.starter-entry[data-src]` rows. Each row has:
  - a `code` with the command;
  - `.starter-src`, whose text is exactly the `src` (file:line);
  - `.starter-category-label`;
  - `.starter-kind` (placeholder rows contain "fill this in");
  - `.lib-status`;
  - the buttons `.starter-open` and `.starter-save` ("Copy to my library").
- Starter rows have no delete or edit controls, and the starter set is never written to storage.
- `.starter-open` loads the command like `.lib-open`, but nothing is marked as being edited. It pre-fills the name and tags, so `.lib-save` creates a user copy.
- `.starter-save` adds a user entry with `source = 'ccsf:' + src`, name and tags from the starter entry. When an identical entry already exists, it is skipped and `.lib-msg` says so.

## R36. Coexistence with Phase 1

- On load, the URL hash or the default example decides `.cmd`. The library and starter set never change `.cmd` until the user clicks Open.
- Library and starter data never appear in `location.hash`. Opening an entry updates the hash to that command via `replaceState`.
- Everything stays text-only DOM. The shim's `innerHTML` trap and R24's static checks still apply, now to `library.js` too.
- (Plumb review) `#scan-desk label {min-width: 0}` and `#scan-desk input[type=file] {width: 100%; min-width: 0}` keep the file input inside 320px.
- The library and starter panels fit the R25 narrow-width rules: no fixed widths over 320px, and rows wrap long commands.

## Open items for Phil (Phase 2)

1. Starter categories are by source area (Active Directory, OT / ICS, Linux, Windows, Pivoting, Recon), added as a `category` field in the fixture. The alternative is by scan purpose (discovery, service detection, scripts).
2. The `pipeline` example (RECON-GUIDE.md:114, `-sL … | grep`) is excluded as not a pure Nmap command. Fragments and broken examples are excluded too, not shown with a label.
3. Import merge only appends and skips exact duplicates. It never overwrites an existing entry, even one with the same id.
4. Storage is `localStorage`, per browser and per file origin. Opening `index.html` from a different path or browser gives a different, empty library; Export/Import is the way to move it.
5. Starter entry names default to `file:line`. A `title` field in the fixture can override them.
