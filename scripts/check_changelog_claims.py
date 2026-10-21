#!/usr/bin/env python3
"""Check the numbers and names the Changelog quotes against the code.

The 4.6.3 entries of Changelog.txt (and the pages that repeat them) quote
limits that live in code: the download budget, the canonicalization budget,
the structure screen's caps, the statement cap, the JSON nesting bound, the
dependency floors. Each was edited by hand, more than once, and a number that
drifts from its constant is a false statement in a security changelog. This
script reads the constants out of the tree and compares them with what the
prose says:

  * CLAIMS is a table of (what, regular expression over the whitespace-
    normalised text, the values its capture groups must equal). Every match in
    every listed file is compared; a claim that matches nowhere is reported as
    NOT FOUND (the prose was reworded: update the table, or the text).
  * Every `backticked` file path, MAX_* constant and CamelCase name the
    Changelog section quotes must exist in the tree.
  * With --numbers, every number written with a thousands separator in the
    section is listed with its line, for a human to read against the code.

Usage:  python scripts/check_changelog_claims.py [--tree PATH] [--version 4.6.3]
        [--numbers] [--strict]

Exit status 1 when a number disagrees with the code (and, with --strict, when a
claim is not found or a name does not resolve). Run it on the tree that will be
tagged, after the last edit of the Changelog.
"""
import argparse
import importlib
import math
import re
import sys
from pathlib import Path

#: Pages that repeat the Changelog's numbers.
PAGES = ['wiki/Security-Model.md', 'wiki/Python-API-OB3.md', 'wiki/Installation.md',
         'openbadgeslib/ob3/clr.py', 'openbadgeslib/ob3/ldp.py',
         'openbadgeslib/ob3/_canon_guard.py', 'openbadgeslib/ob3/_structure_screen.py',
         'openbadgeslib/util.py', 'pyproject.toml']

MODULES = {
    'util': 'openbadgeslib.util',
    'canon': 'openbadgeslib.ob3._canon_guard',
    'screen': 'openbadgeslib.ob3._structure_screen',
    'ldp': 'openbadgeslib.ob3.ldp',
    'safejson': 'openbadgeslib._safejson',
}


def load_constants(tree):
    sys.path.insert(0, str(tree))
    mods = {key: importlib.import_module(name) for key, name in MODULES.items()}
    for mod in mods.values():
        assert Path(mod.__file__).resolve().is_relative_to(Path(tree).resolve()), (
            '%s was imported from outside --tree' % mod.__name__)
    c = {}
    for key, mod in mods.items():
        for name, value in vars(mod).items():
            if name.lstrip('_').isupper() and isinstance(value, (int, float)):
                c['%s.%s' % (key, name)] = value
    c['screen.CLR_TYPED'] = 2 * c['screen.MAX_TYPED_NODES']
    c['screen.CLR_ENTRIES'] = 2 * c['screen.MAX_TYPE_ENTRIES']
    c['screen.CLR_NODES'] = 2 * c['screen.MAX_NODES']
    # N distinct values of one property cost N^2/2 comparisons: the most that
    # fits the pair budget.
    pairs = c['canon.MAX_NODE_MAP_PAIRS']
    c['canon.MAX_ONE_PROPERTY'] = math.isqrt(2 * pairs)
    c['ldp.DOC_KIB'] = c['ldp.MAX_LDP_DOCUMENT_BYTES'] // 1024
    return c


N = r'(\d[\d,]*(?:\.\d+)?)'

#: (what, regex, [constant per capture group]). Whitespace is normalised to
#: single spaces before matching, so a claim may span lines.
CLAIMS = [
    ('download budget', r'(\d+)-second (?:time )?budget', ['util.MAX_DOWNLOAD_SECONDS']),
    ('download per-operation timeout',
     r'bounded per operation \((\d+) seconds\)', ['util._SOCKET_TIMEOUT']),
    ('download size cap', r'(\d+) MiB', ['util.MAX_DOWNLOAD_SIZE_MIB']),
    ('canonicalization work budget', r'budget is ' + N + r' model units',
     ['canon.MAX_CANON_WORK']),
    ('canonicalization CPU allowance', r'CPU-time allowance of ' + N + r' s',
     ['canon.MAX_CANON_SECONDS']),
    ('document cap', r'(\d+) KiB (?:document )?cap', ['ldp.DOC_KIB']),
    ('document cap (signing)', r'document over (\d+) KiB', ['ldp.DOC_KIB']),
    ('statement cap', r'more than ' + N + r' statements', ['ldp.MAX_DELEGATED_QUADS']),
    ('screen: typed objects, type entries, objects',
     r'more than ' + N + r' typed objects, ' + N + r' type entries or ' + N
     + r' objects', ['screen.MAX_TYPED_NODES', 'screen.MAX_TYPE_ENTRIES',
                     'screen.MAX_NODES']),
    ('screen: types per node', r'lists more than (\d+)', ['screen.MAX_TYPES_PER_NODE']),
    ('screen: @context entries',
     r'@context` array of more than (\d+) entries or ' + N + r' entries in all',
     ['screen.MAX_CONTEXT_ENTRIES', 'screen.MAX_CONTEXT_ENTRIES_TOTAL']),
    ('screen: the CLR limits are twice those',
     r'CLR of more than ' + N + r' typed objects or ' + N + r' type entries',
     ['screen.CLR_TYPED', 'screen.CLR_ENTRIES']),
    ('screen: the CLR object limit', r'and ' + N + r' objects in all',
     ['screen.CLR_NODES']),
    ('pair budget', r'a document over ' + N + r' of them', ['canon.MAX_NODE_MAP_PAIRS']),
    ('values of one property', r'one property of ' + N + r' distinct values',
     ['canon.MAX_ONE_PROPERTY']),
    ('JSON nesting', r'(\d+) levels(?: of nesting|, no lone surrogate)',
     ['safejson.MAX_JSON_DEPTH']),
]


def number(text):
    text = text.replace(',', '')
    return float(text) if '.' in text else int(text)


def section(text, version):
    start = re.search(r'^\* v%s\b.*$' % re.escape(version), text, re.M)
    if not start:
        sys.exit('no "* v%s" section in the Changelog' % version)
    end = re.search(r'^\* v\d', text[start.end():], re.M)
    return text[start.start():start.end() + end.start() if end else len(text)]


def check_claims(c, texts):
    problems, notes = [], []
    for what, pattern, names in CLAIMS:
        found = 0
        for label, text in texts.items():
            flat = re.sub(r'\s+', ' ', text)
            for m in re.finditer(pattern, flat):
                found += 1
                for group, name in zip(m.groups(), names):
                    want = c.get(name)
                    if want is None and name == 'util.MAX_DOWNLOAD_SIZE_MIB':
                        want = c['util.MAX_DOWNLOAD_SIZE'] // 2 ** 20
                    if number(group) != want:
                        problems.append('%s: %s says %s, the code has %s (%s)'
                                        % (label, what, group, want, name))
        if not found:
            notes.append('NOT FOUND: %s (/%s/)' % (what, pattern))
    return problems, notes


def check_names(tree, changelog_section):
    code = '\n'.join(p.read_text(encoding='utf-8', errors='replace')
                     for p in Path(tree, 'openbadgeslib').rglob('*.py'))
    unresolved = []
    for token in sorted(set(re.findall(r'`([^`\n]+)`', changelog_section))):
        if re.fullmatch(r'[\w./-]+\.(?:py|md|yml|toml|txt)', token):
            if not (Path(tree, token).exists()
                    or Path(tree, 'openbadgeslib', token).exists()):
                unresolved.append('path does not exist: %s' % token)
        elif re.fullmatch(r'(?:[\w]+\.)*MAX_[A-Z_]+', token):
            if not re.search(r'\b%s\b' % token.rsplit('.', 1)[-1], code):
                unresolved.append('constant not in the code: %s' % token)
        elif re.fullmatch(r'(?:[a-z_0-9]+\.)*(?:OB3|OB2|Open|Canonicalization)[A-Za-z0-9]+',
                          token):
            if not re.search(r'\b%s\b' % token.rsplit('.', 1)[-1], code):
                unresolved.append('name not in the code: %s' % token)
    return unresolved


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--tree', default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument('--version', default='4.6.3')
    ap.add_argument('--numbers', action='store_true')
    ap.add_argument('--strict', action='store_true')
    args = ap.parse_args()
    tree = Path(args.tree).resolve()

    c = load_constants(tree)
    sec = section((tree / 'Changelog.txt').read_text(encoding='utf-8'), args.version)
    texts = {'Changelog %s' % args.version: sec}
    for page in PAGES:
        if (tree / page).exists():
            texts[page] = (tree / page).read_text(encoding='utf-8')

    problems, notes = check_claims(c, texts)
    unresolved = check_names(tree, sec)

    if args.numbers:
        print('Numbers with a thousands separator in the %s section:' % args.version)
        for i, line in enumerate(sec.splitlines(), 1):
            for m in re.finditer(r'\b\d{1,3}(?:,\d{3})+\b', line):
                print('  line %4d  %-10s %s' % (i, m.group(), line.strip()[:70]))
    for line in problems:
        print('MISMATCH   ', line)
    for line in unresolved:
        print('UNRESOLVED ', line)
    for line in notes:
        print('note       ', line)
    print('%d mismatch(es), %d unresolved name(s), %d claim(s) not found'
          % (len(problems), len(unresolved), len(notes)))
    bad = bool(problems) or (args.strict and (notes or unresolved))
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
