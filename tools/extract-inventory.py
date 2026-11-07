#!/usr/bin/env python3
"""Build the Nmap flag inventory from real Nmap source (B3 / REQUIREMENTS.md R27).

Usage:
  extract-inventory.py SOURCE                 print inventory (SOURCE = nmap.cc or nmap-<v>.tar.bz2)
  extract-inventory.py --fetch 7.993          download from nmap.org, verify SHA256 against nmap.org's digest
  extract-inventory.py SOURCE --check         compare with coverage.txt and catalog.txt; exit 1 on drift
  extract-inventory.py SOURCE --write-coverage  rewrite coverage.txt's hash line and registration list

Standard library only. Never falls back to stored data: if the source cannot be read or
downloaded, it exits non-zero.
"""
import argparse
import hashlib
import io
import re
import sys
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = 'https://nmap.org/dist/'
ARITY = {'no_argument': 'no', 'required_argument': 'required', 'optional_argument': 'optional'}
HEADER = 'Source registration → argument type\n'


def die(msg, code=2):
    print('extract-inventory: ' + msg, file=sys.stderr)
    sys.exit(code)


def read_tar_member(data, suffix='/nmap.cc'):
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as tf:
        for m in tf.getmembers():
            # Only a regular file directly under the top-level directory; never extract to disk.
            if m.isfile() and m.name.count('/') == 1 and m.name.endswith(suffix):
                return m.name, tf.extractfile(m).read()
    die('nmap.cc not found in archive')


def fetch(version):
    if not re.fullmatch(r'\d+\.\d+(\.\d+)?', version):
        die('version must look like 7.993')
    name = f'nmap-{version}.tar.bz2'
    try:
        tarball = urllib.request.urlopen(DIST + name, timeout=120).read()
        digest = urllib.request.urlopen(f'{DIST}sigs/{name}.digest.txt', timeout=60).read().decode('utf-8', 'replace')
    except Exception as e:  # network failure must be loud, never faked
        die(f'network fetch failed for {name}: {e}')
    m = re.search(r'SHA256\s*=\s*((?:[0-9A-Fa-f]{8}\s*){8})', digest)
    if not m:
        die('SHA256 line not found in nmap.org digest file')
    want = re.sub(r'\s+', '', m.group(1)).lower()
    got = hashlib.sha256(tarball).hexdigest()
    if got != want:
        die(f'tarball SHA256 mismatch: got {got}, nmap.org says {want}')
    member, src = read_tar_member(tarball)
    return {'release': version, 'tarball': name, 'tarball_sha256': got, 'member': member, 'src': src}


def load(source):
    p = Path(source)
    if not p.is_file():
        die(f'no such file: {source}')
    data = p.read_bytes()
    if p.name.endswith(('.tar.bz2', '.tgz', '.tar.gz', '.tar')):
        member, src = read_tar_member(data)
        return {'tarball': p.name, 'tarball_sha256': hashlib.sha256(data).hexdigest(), 'member': member, 'src': src}
    return {'member': p.name, 'src': data}


def extract(src_bytes):
    text = src_bytes.decode('utf-8', 'replace')
    start = text.find('struct option long_options[]')
    if start < 0:
        die('long_options[] table not found')
    end = text.find('{0, 0, 0, 0}', start)
    if end < 0:
        die('long_options[] terminator not found')
    table = text[start:end]
    longs, skipped = [], 0
    for m in re.finditer(r'\{\s*([^,{}]+?)\s*,\s*(no_argument|required_argument|optional_argument)\s*,', table):
        lit = re.fullmatch(r'"([^"]+)"', m.group(1))
        if lit:
            longs.append((lit.group(1), ARITY[m.group(2)]))
        else:
            skipped += 1  # non-literal registration (e.g. the encoded novelty option)
    sm = re.search(r'getopt_long_only\s*\(\s*argc\s*,\s*argv\s*,\s*"([^"]*)"', text)
    if not sm:
        die('getopt_long_only short-option string not found')
    return {'long': longs, 'short': sm.group(1), 'nonliteral': skipped, 'sha256': hashlib.sha256(src_bytes).hexdigest()}


def short_options(s):
    out, i = [], 0
    while i < len(s):
        c = s[i]; i += 1
        n = 0
        while i < len(s) and s[i] == ':':
            n += 1; i += 1
        out.append((c, ['no', 'required', 'optional'][min(n, 2)]))
    return out


def render(info, meta):
    lines = []
    if meta.get('release'):
        lines.append(f"Nmap {meta['release']} · {DIST}{meta['tarball']}")
    if meta.get('tarball_sha256'):
        lines.append(f"{meta['tarball']} SHA256: {meta['tarball_sha256']}")
    lines.append(f"nmap.cc SHA256: {info['sha256']}")
    lines.append(f"Short options: {info['short']}")
    lines.append(f"{len(info['long'])} literal long-option registrations; {info['nonliteral']} non-literal skipped.")
    lines.append('')
    lines.append(HEADER.rstrip('\n'))
    lines += [f'{n} {a}' for n, a in info['long']]
    return '\n'.join(lines) + '\n'


def catalog_forms(text):
    forms = {}
    for line in text.strip().splitlines():
        if line.startswith('# ') or not line.strip():
            continue
        for f in line.split('|')[0].split():
            key = f.rstrip('@?')
            forms[key] = 'required' if f.endswith('@') else 'optional' if f.endswith('?') else 'no'
    return forms


def check(info):
    problems = []
    cov = (ROOT / 'coverage.txt').read_text()
    hm = re.search(r'nmap\.cc SHA256:\s*([0-9a-f]{64})', cov)
    if not hm or hm.group(1) != info['sha256']:
        problems.append(f"coverage.txt nmap.cc SHA256 {hm.group(1) if hm else '(missing)'} != source {info['sha256']}")
    if HEADER not in cov:
        problems.append('coverage.txt lacks the registration header')
    else:
        listed = [tuple(l.split(' ', 1)) for l in cov.split(HEADER, 1)[1].strip().splitlines() if l.strip()]
        if listed != info['long']:
            a, b = set(listed), set(info['long'])
            for x in sorted(b - a):
                problems.append(f'coverage.txt missing registration: {x[0]} {x[1]}')
            for x in sorted(a - b):
                problems.append(f'coverage.txt lists registration absent upstream: {x[0]} {x[1]}')
            if a == b:
                problems.append('coverage.txt registration order differs from source')
    forms = catalog_forms((ROOT / 'catalog.txt').read_text())
    upstream_long = {}
    for name, arity in info['long']:
        upstream_long[name] = arity
        hit = forms.get('--' + name, forms.get('-' + name))
        if hit is None:
            problems.append(f'catalog.txt missing long option --{name}')
        elif hit != arity:
            problems.append(f'catalog.txt arity for --{name}: {hit} (source: {arity})')
    for key in forms:
        if key.startswith('--') and key[2:] not in upstream_long:
            problems.append(f'catalog.txt long form {key} is not a literal upstream registration')
    for letter, arity in short_options(info['short']):
        family = [k for k in forms if k.startswith('-' + letter) and not k.startswith('--')]
        if not family:
            problems.append(f'catalog.txt missing short option -{letter} ({arity})')
        elif ('-' + letter) in forms and forms['-' + letter] != arity and arity != 'optional':
            problems.append(f"catalog.txt arity for -{letter}: {forms['-' + letter]} (source: {arity})")
    return problems


def write_coverage(info):
    path = ROOT / 'coverage.txt'
    cov = path.read_text()
    cov = re.sub(r'nmap\.cc SHA256:\s*[0-9a-f]{64}', 'nmap.cc SHA256: ' + info['sha256'], cov)
    head = cov.split(HEADER, 1)[0] if HEADER in cov else cov + '\n'
    path.write_text(head + HEADER + '\n'.join(f'{n} {a}' for n, a in info['long']) + '\n')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('source', nargs='?', help='nmap.cc or nmap-<version>.tar.bz2')
    ap.add_argument('--fetch', metavar='VERSION', help='download and verify this release from nmap.org')
    ap.add_argument('--check', action='store_true', help='compare with coverage.txt and catalog.txt')
    ap.add_argument('--write-coverage', action='store_true', help='rewrite coverage.txt from source')
    a = ap.parse_args(argv)
    if bool(a.source) == bool(a.fetch):
        ap.error('give exactly one of SOURCE or --fetch VERSION')
    meta = fetch(a.fetch) if a.fetch else load(a.source)
    info = extract(meta['src'])
    sys.stdout.write(render(info, meta))
    if a.write_coverage:
        write_coverage(info)
        print('coverage.txt updated', file=sys.stderr)
    if a.check:
        problems = check(info)
        for p in problems:
            print('DRIFT: ' + p)
        if problems:
            return 1
        print('OK: catalog.txt and coverage.txt match the source inventory.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
