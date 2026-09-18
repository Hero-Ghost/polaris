"""Verification for the Hebrew rewrite. Run before and after each stage."""
import re, sys, json, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP = {'dist', 'build', '__pycache__', 'squirreldisk_src', 'graphify-out', '.git', '.pytest_cache'}
HEB  = re.compile(r'[֐-׿]')

# Terms that must not appear after the rewrite (see glossary 4.4)
BANNED = ['ווינדוס', 'בריכות', 'מפת כריות', 'היוריסטית', 'כוונת ציד',
          'אנא ', 'סה"כ']
# NOTE: 'דרייבר' intentionally NOT banned - decision in 4.3 kept the existing term.

def files():
    for p in ROOT.rglob('*'):
        if p.suffix not in {'.py', '.js', '.html'}: continue
        if SKIP & set(p.parts): continue
        if p.name == 'verify_he.py': continue
        yield p

def _i18n_bounds(lines):
    lo = next(i for i, l in enumerate(lines) if '  he: {' in l)
    mid = next(i for i, l in enumerate(lines) if '  en: {' in l)
    hi = next(i for i, l in enumerate(lines) if l.strip() == '};' and i > mid)
    return lo, mid, hi

def i18n_tables():
    lines = (ROOT / 'frontend' / 'app.js').read_text(encoding='utf-8').split('\n')
    lo, mid, hi = _i18n_bounds(lines)
    he = '\n'.join(lines[lo:mid])
    en = '\n'.join(lines[mid:hi + 1])
    key = lambda s: set(re.findall(r'^\s{4}([A-Za-z0-9_]+):\s*[\'"]', s, re.M))
    return key(he), key(en), en

def placeholders(path):
    """Map every Hebrew-bearing line to its placeholder multiset."""
    out = {}
    pat = r'\$\{[^}]*\}' if path.suffix in {'.js', '.html'} else r'\{[^}]*\}'
    for n, line in enumerate(path.read_text(encoding='utf-8').split('\n'), 1):
        if HEB.search(line):
            out[n] = sorted(re.findall(pat, line))
    return out

def main():
    full = '--full' in sys.argv
    errors, warnings = [], []

    # 1. encoding
    for p in files():
        raw = p.read_bytes()
        if raw.startswith(b'\xef\xbb\xbf'):
            errors.append(f'BOM found: {p.relative_to(ROOT)}')
        try: raw.decode('utf-8')
        except UnicodeDecodeError: errors.append(f'not UTF-8: {p.relative_to(ROOT)}')

    # 2. i18n key parity
    he, en, en_block = i18n_tables()
    for k in sorted(he - en): errors.append(f'key missing in I18N.en: {k}')
    for k in sorted(en - he): errors.append(f'key missing in I18N.he: {k}')

    # 3. Hebrew leaking into the English table
    for m in re.finditer(r'^\s{4}([A-Za-z0-9_]+):\s*[\'"]((?:[^\'"\\]|\\.)*)[\'"]', en_block, re.M):
        k, v = m.group(1), m.group(2)
        if HEB.search(v): errors.append(f'Hebrew inside I18N.en: {k} = {v[:40]}')

    # 4. banned terms
    for p in files():
        txt = p.read_text(encoding='utf-8')
        for term in BANNED:
            c = txt.count(term)
            if c: (errors if full else warnings).append(
                f'banned term {term!r} x{c}: {p.relative_to(ROOT)}')

    # 5. placeholder snapshot (compare against baseline.json)
    snap = {str(p.relative_to(ROOT)): placeholders(p) for p in files()}
    base = ROOT / 'tools' / 'baseline.json'
    if base.exists():
        old = json.loads(base.read_text(encoding='utf-8'))
        for f, lines in old.items():
            new = snap.get(f, {})
            old_all = sorted(x for v in lines.values() for x in v)
            new_all = sorted(x for v in new.values() for x in v)
            if old_all != new_all:
                missing = set(old_all) - set(new_all)
                added   = set(new_all) - set(old_all)
                errors.append(f'PLACEHOLDER MISMATCH in {f}: '
                              f'lost={sorted(missing)} gained={sorted(added)}')
    else:
        base.write_text(json.dumps(snap, ensure_ascii=False, indent=1), encoding='utf-8')
        print('baseline written ->', base)

    # 6. hardcoded Hebrew outside I18N
    appjs_lines = (ROOT / 'frontend' / 'app.js').read_text(encoding='utf-8').split('\n')
    lo, _mid, hi = _i18n_bounds(appjs_lines)
    stray = [i + 1 for i, l in enumerate(appjs_lines) if HEB.search(l) and not lo <= i <= hi]
    html_stray = [n for n, l in enumerate(
        (ROOT / 'frontend' / 'index.html').read_text(encoding='utf-8').split('\n'), 1)
        if HEB.search(l) and 'data-i18n' not in l]
    print(f'\nhardcoded Hebrew  app.js: {len(stray)}   index.html: {len(html_stray)}')
    print(f'i18n keys  he: {len(he)}  en: {len(en)}')

    for w in warnings: print('  WARN ', w)
    for e in errors:   print('  ERROR', e)
    print(f'\n{len(errors)} errors, {len(warnings)} warnings')
    return 1 if errors else 0

if __name__ == '__main__':
    sys.exit(main())
