"""
get_linux_libs.py — Download Linux .so files from Ubuntu 22.04 (jammy) mirrors.

Targets chosen for cross-compiler invariance tests:
  libssl.so.3      → compare with winhttp/schannel (TLS design patterns)
  libsqlite3.so.0  → compare with py_sqlite (same source, GCC vs MSVC)
  libpython3.10.so → compare with python312 (same CPython source)
  libc.so.6        → compare with kernel32/ntdll/vcruntime140

Ubuntu 22.04 uses .xz compression in .deb → Python tarfile handles it natively.
"""
import io, os, sys, tarfile, struct, urllib.request

OUT_DIR = 'linux_libs'
os.makedirs(OUT_DIR, exist_ok=True)

DEBIAN_MIRROR = 'https://ftp.debian.org/debian'

# Packages to fetch: (package_name, so_filename, note)
WANT = [
    ('libssl3',       'libssl.so.3',         'OpenSSL 3 GCC — compare with winhttp/schannel'),
    ('libsqlite3-0',  'libsqlite3.so.0',     'SQLite3 GCC — compare with py_sqlite MSVC'),
    ('libpython3.11', 'libpython3.11.so.1.0','CPython 3.11 GCC — compare with python312 MSVC'),
    ('libc6',         'libc.so.6',           'glibc — Linux kernel32+ntdll+vcruntime analog'),
    ('libx264-164',   'libx264.so.164',      'H.264 codec — SIMD-heavy, bit manipulation, entropy coder'),
    ('libopus0',      'libopus.so.0',        'Opus audio codec — CELT/SILK hybrid, DSP patterns'),
]


def find_package_url(pkg_name: str) -> str | None:
    """Query Debian bookworm Packages index to find current .deb URL."""
    import gzip
    index_url = f'{DEBIAN_MIRROR}/dists/bookworm/main/binary-amd64/Packages.gz'
    print(f'    Querying Debian package index for {pkg_name}...')
    try:
        req = urllib.request.Request(index_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
        text = gzip.decompress(raw).decode('utf-8', errors='replace')
    except Exception as e:
        print(f'    Failed to fetch index: {e}')
        return None

    # Parse stanza blocks
    for block in text.split('\n\n'):
        lines = dict(
            line.split(': ', 1) for line in block.splitlines()
            if ': ' in line
        )
        if lines.get('Package') == pkg_name and lines.get('Architecture') == 'amd64':
            filename = lines.get('Filename')
            if filename:
                return f'{DEBIAN_MIRROR}/{filename}'
    return None


PACKAGES = []
for pkg_name, so_name, note in WANT:
    PACKAGES.append({'name': pkg_name, 'so': so_name, 'note': note})


def parse_ar(data: bytes):
    """Parse ar archive, yield (name, member_data) pairs."""
    assert data[:8] == b'!<arch>\n', 'Not an ar archive'
    pos = 8
    while pos < len(data):
        if pos + 60 > len(data):
            break
        hdr  = data[pos:pos+60]
        name = hdr[0:16].decode('ascii', errors='replace').strip()
        size = int(hdr[48:58].strip())
        pos += 60
        member_data = data[pos:pos+size]
        pos += size
        if size % 2:
            pos += 1   # ar pads to even byte
        yield name, member_data


def extract_so_from_deb(deb_data: bytes, so_name: str, out_path: str) -> bool:
    """Extract a single .so file from a .deb package."""
    for ar_name, ar_data in parse_ar(deb_data):
        if not ar_name.startswith('data.tar'):
            continue
        # Detect compression from name
        if ar_name.endswith('.xz'):
            mode = 'r:xz'
        elif ar_name.endswith('.gz'):
            mode = 'r:gz'
        elif ar_name.endswith('.bz2'):
            mode = 'r:bz2'
        else:
            mode = 'r:*'
        try:
            with tarfile.open(fileobj=io.BytesIO(ar_data), mode=mode) as tar:
                for member in tar.getmembers():
                    bn = os.path.basename(member.name)
                    # Match exact name OR versioned variant (e.g. libssl.so.3.0.2)
                    if bn == so_name or bn.startswith(so_name.split('.so')[0] + '.so'):
                        f = tar.extractfile(member)
                        if f:
                            content = f.read()
                            if len(content) > 1000:   # skip tiny stubs
                                with open(out_path, 'wb') as out:
                                    out.write(content)
                                print(f'    Extracted: {bn} → {out_path} ({len(content)//1024:,} KB)')
                                return True
        except Exception as e:
            print(f'    tar error ({ar_name}): {e}')
    return False


def download_and_extract(pkg: dict) -> str | None:
    so_path = os.path.join(OUT_DIR, pkg['so'])
    if os.path.exists(so_path):
        size = os.path.getsize(so_path)
        print(f'  {pkg["name"]}: already exists ({size//1024:,} KB) — skipping')
        return so_path

    url = find_package_url(pkg['name'])
    if url is None:
        print(f'  {pkg["name"]}: could not find in Debian package index')
        return None
    print(f'  {pkg["name"]}: downloading {url.split("/")[-1]} ...')
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=60) as resp:
            deb_data = resp.read()
        print(f'    Downloaded: {len(deb_data)//1024:,} KB')
    except Exception as e:
        print(f'    FAILED download: {e}')
        return None

    print(f'    Extracting {pkg["so"]} ...')
    ok = extract_so_from_deb(deb_data, pkg['so'], so_path)
    if not ok:
        # Try without version suffix (libssl.so.3 → libssl.so)
        base = pkg['so'].rsplit('.', 1)[0]
        ok = extract_so_from_deb(deb_data, base, so_path)
    if not ok:
        print(f'    FAILED: could not find {pkg["so"]} in package')
        # List what IS in the package for debugging
        for ar_name, ar_data in parse_ar(deb_data):
            if ar_name.startswith('data.tar'):
                try:
                    with tarfile.open(fileobj=io.BytesIO(ar_data), mode='r:*') as tar:
                        libs = [m.name for m in tar.getmembers() if '.so' in m.name]
                        print(f'    Available .so files: {libs[:10]}')
                except Exception:
                    pass
        return None

    return so_path


print('Downloading Linux .so files from Ubuntu 22.04 mirrors...\n')
results = {}
for pkg in PACKAGES:
    print(f'\n[{pkg["name"]}] {pkg["note"]}')
    path = download_and_extract(pkg)
    if path:
        results[pkg['name']] = path

print(f'\n{"="*55}')
print(f'Downloaded {len(results)}/{len(PACKAGES)} libraries:')
for name, path in results.items():
    size = os.path.getsize(path)
    print(f'  {name:<20} {size//1024:>6,} KB  →  {path}')

if results:
    print(f'\nNext: py -3.13 pcode_extractor.py  (ELF support added separately)')
