# aanetsphere.py
# Product Name: AANetSphere
# Internal Metadata (do not remove):
#   signature.owner: Abhishek Awasthi
#   signature.created: 2026-03-09
#   signature.note: This comment embeds the full-name signature for provenance.
# Author: M365 Copilot for Abhishek Awasthi
# Features: Analyze, Overlap Report, Summaries, Dual-Stack Mapping, Host Planner, VLSM Allocate-by-Hosts,
# PQC-hybrid Password Vault (AES-256-GCM + Argon2id/Scrypt + Kyber512 optional), Excel export.
# Enhanced: Full Clear action; Help tooltips ('?') for Host Planner & VLSM; Help->About dialog.

import json, math, os, base64, secrets, datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from ipaddress import ip_network, IPv4Network, IPv6Network, ip_address
from typing import List, Tuple, Dict, Optional, Union
from pathlib import Path as _Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    CRYPTO_OK = True
except Exception:
    CRYPTO_OK = False

try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_OK = True
except Exception:
    ARGON2_OK = False

try:
    from pqcrypto.kem.kyber512 import generate_keypair, encrypt as kyber_encaps, decrypt as kyber_decaps
    KYBER_OK = True
except Exception:
    KYBER_OK = False

MAX_EXPANDED_ROWS = 50000
MAX_OVERLAP_PAIRS = 100000
MAX_HOSTPLAN_ROWS_PER_REQ = 100
Network = Union[IPv4Network, IPv6Network]

def b64e(b: bytes) -> str: return base64.b64encode(b).decode('ascii')

def b64d(s: str) -> bytes: return base64.b64decode(s.encode('ascii'))

def derive_key_argon2id(password: str, salt: bytes, *, length: int = 32, time_cost: int = 3, mem_kib: int = 65536, parallelism: int = 2) -> bytes:
    return hash_secret_raw(secret=password.encode('utf-8'), salt=salt, time_cost=time_cost, memory_cost=mem_kib, parallelism=parallelism, hash_len=length, type=Type.ID)

def derive_key_scrypt(password: str, salt: bytes, *, length: int = 32, n: int = 2**15, r: int = 8, p: int = 1) -> bytes:
    return Scrypt(salt=salt, length=length, n=n, r=r, p=p).derive(password.encode('utf-8'))

IPv4_RANGES = {'Private':[ip_network('10.0.0.0/8'), ip_network('172.16.0.0/12'), ip_network('192.168.0.0/16')], 'CGNAT':[ip_network('100.64.0.0/10')], 'Loopback':[ip_network('127.0.0.0/8')], 'Link-Local':[ip_network('169.254.0.0/16')], 'Multicast':[ip_network('224.0.0.0/4')], 'Reserved':[ip_network('240.0.0.0/4')], 'Documentation':[ip_network('192.0.2.0/24'), ip_network('198.51.100.0/24'), ip_network('203.0.113.0/24')], 'Benchmarking':[ip_network('198.18.0.0/15')]}
IPv6_RANGES = {'Unique-Local (ULA)':[ip_network('fc00::/7')], 'Link-Local':[ip_network('fe80::/10')], 'Multicast':[ip_network('ff00::/8')], 'Loopback':[ip_network('::1/128')], 'Unspecified':[ip_network('::/128')], 'Documentation':[ip_network('2001:db8::/32')], 'Global Unicast':[ip_network('2000::/3')]}

def classify_ipv4_network(net: IPv4Network) -> str:
    for label, ranges in IPv4_RANGES.items():
        for r in ranges:
            if net.subnet_of(r): return label
    return 'Public'

def classify_ipv6_network(net: IPv6Network) -> str:
    for label, ranges in IPv6_RANGES.items():
        for r in ranges:
            if net.subnet_of(r): return label
    try:
        if net.subnet_of(ip_network('2000::/3')): return 'Global Unicast'
    except Exception: pass
    return 'Other/Reserved'

def usable_hosts_ipv4(prefix_len: int) -> int:
    if prefix_len == 32: return 1
    if prefix_len == 31: return 2
    if prefix_len < 0 or prefix_len > 32: return 0
    return max(0, (2 ** (32 - prefix_len)) - 2)

def count_addresses(net: Network) -> int: return net.num_addresses

def net_bounds(n: Network) -> Tuple[int,int]:
    start = int(n.network_address)
    return start, start + n.num_addresses - 1

def analyze_split(parent: Network, *, target_prefix: Optional[int] = None, desired_subnets: Optional[int] = None) -> Tuple[int,int,int]:
    if target_prefix is None and desired_subnets is None: raise ValueError('Either target_prefix or desired_subnets must be provided')
    base_prefix = parent.prefixlen; max_bits = 32 if isinstance(parent, IPv4Network) else 128
    if target_prefix is None:
        delta = math.ceil(math.log2(max(1, desired_subnets))); target_prefix = base_prefix + delta
    elif target_prefix < base_prefix: raise ValueError('target_prefix must be >= parent prefix')
    if target_prefix > max_bits: raise ValueError('target_prefix exceeds address size')
    delta = target_prefix - base_prefix
    return target_prefix, 2 ** delta, 2 ** (max_bits - target_prefix)

def expand_to_prefix(parent: Network, target_prefix: int, include_intermediate: bool=False) -> List[Tuple[Network,int,Optional[Network]]]:
    rows = [(parent, 0, None)]
    if target_prefix == parent.prefixlen: return rows
    current_level = [(parent, None)]; level = 0
    while current_level:
        next_level = []
        for net, p in current_level:
            if net.prefixlen == target_prefix: continue
            children = list(net.subnets(new_prefix=net.prefixlen + 1))
            if include_intermediate:
                for ch in children: rows.append((ch, level + 1, net))
            if (net.prefixlen + 1) < target_prefix:
                for ch in children: next_level.append((ch, net))
        current_level = next_level; level += 1
        if level > 256: break
    if not include_intermediate:
        final_subnets = list(parent.subnets(new_prefix=target_prefix))
        rows = [(parent, 0, None)]
        for ch in final_subnets: rows.append((ch, 1, parent))
    return rows

def detect_overlaps(items: List[Dict]) -> Tuple[List[Dict], Dict[str,bool]]:
    per_ver = {'IPv4': [], 'IPv6': []}
    for d in items:
        n = ip_network(d['cidr'], strict=False)
        start, end = net_bounds(n)
        per_ver[d['ip_version']].append((start, end, d['cidr'], d['root']))
    pairs, flags = [], {}
    for ver, arr in per_ver.items():
        if not arr: continue
        arr.sort(key=lambda x: (x[0], x[1]))
        active = []
        for i, (start, end, cidr, root) in enumerate(arr):
            active = [a for a in active if a[1] >= start]
            for (a_start, a_end, a_cidr, a_root) in active:
                if root == a_root: continue
                if a_end >= start:
                    ov_first, ov_last = max(a_start, start), min(a_end, end)
                    pairs.append({'ip_version': ver,'cidr_a': a_cidr,'root_a': a_root,'cidr_b': cidr,'root_b': root,'overlap_first': str(ip_address(ov_first)),'overlap_last': str(ip_address(ov_last))})
                    flags[a_cidr] = True; flags[cidr] = True
                    if len(pairs) >= MAX_OVERLAP_PAIRS: return pairs, flags
            active.append((start, end, cidr, root)); active.sort(key=lambda x: x[1])
    return pairs, flags

def summarize_networks(items: List[Dict], *, final_only: bool=False) -> Dict[str,List[str]]:
    from ipaddress import collapse_addresses
    by_ver = {'IPv4': [], 'IPv6': []}; max_level = {}
    for d in items:
        r, lvl = d['root'], d['level']
        if r not in max_level or lvl > max_level[r]: max_level[r] = lvl
    for d in items:
        if final_only and d['level'] != max_level.get(d['root'], d['level']): continue
        by_ver[d['ip_version']].append(ip_network(d['cidr'], strict=False))
    out = {}
    for ver, nets in by_ver.items(): out[ver] = [str(n) for n in collapse_addresses(nets)] if nets else []
    return out

def dual_stack_map_ipv4_to_ipv6(items: List[Dict], ipv6_base: str, target_ipv6_prefix: int, mode: str='sequential') -> List[Dict]:
    base = ip_network(ipv6_base, strict=False)
    if not isinstance(base, IPv6Network): raise ValueError('IPv6 base must be an IPv6 prefix')
    if target_ipv6_prefix < base.prefixlen: raise ValueError('Target IPv6 prefix must be longer (>=) than base prefix')
    max_level = {}
    for d in items:
        r, lvl = d['root'], d['level']
        if r not in max_level or lvl > max_level[r]: max_level[r] = lvl
    leaves_v4, leaves_meta = [], []
    for d in items:
        if d['ip_version'] != 'IPv4': continue
        if d['level'] != max_level.get(d['root'], d['level']): continue
        leaves_v4.append(ip_network(d['cidr'], strict=False)); leaves_meta.append((d['cidr'], d['root']))
    total_slots = 2 ** (target_ipv6_prefix - base.prefixlen)
    if len(leaves_v4) > total_slots: raise ValueError(f'IPv6 base {base} cannot fit {len(leaves_v4)} subprefixes of /{target_ipv6_prefix}. Available: {total_slots}')
    allocs = list(base.subnets(new_prefix=target_ipv6_prefix))
    leaves_sorted = sorted(zip(leaves_v4, leaves_meta), key=lambda x: int(x[0].network_address))
    mappings = []
    for idx, (v4, (cidr, root)) in enumerate(leaves_sorted): mappings.append({'ipv4': str(v4), 'root': root, 'ipv6_alloc': str(allocs[idx]), 'note': mode})
    return mappings

def min_prefix_for_hosts_ipv4(hosts: int) -> int:
    if hosts <= 0: raise ValueError('Host requirement must be positive')
    if hosts == 1: return 32
    if hosts == 2: return 31
    for p in range(30, -1, -1):
        if usable_hosts_ipv4(p) >= hosts: return p
    return 0

def compute_host_plan(items: List[Dict], host_reqs: List[int], ipver: str='IPv4') -> List[Dict]:
    if ipver not in ('IPv4','IPv6'): ipver = 'IPv4'
    max_level = {}
    for d in items:
        r, lvl = d['root'], d['level']
        if r not in max_level or lvl > max_level[r]: max_level[r] = lvl
    leaves = [d for d in items if d['ip_version']==ipver and d['level']==max_level.get(d['root'], d['level'])]
    def leaf_key(d: Dict):
        n = ip_network(d['cidr'], strict=False); na = int(n.network_address)
        return (d['size'], na)
    leaves_sorted = sorted(leaves, key=leaf_key)
    plan = []
    for h in host_reqs:
        if ipver=='IPv4':
            try: min_p = min_prefix_for_hosts_ipv4(h); min_usable = usable_hosts_ipv4(min_p)
            except Exception: min_p, min_usable = None, None
        else:
            if h <= 0: min_p, min_usable = None, None
            else:
                bits = math.ceil(math.log2(h)); p = 128 - bits
                min_p, min_usable = max(0, min(128, p)), 2 ** (128 - max(0, min(128, p)))
        candidates = []
        for d in leaves_sorted:
            ok = d['usable'] >= h if ipver=='IPv4' else d['size'] >= h
            if ok: candidates.append(d)
            if len(candidates) >= MAX_HOSTPLAN_ROWS_PER_REQ: break
        if not candidates:
            plan.append({'hosts': h,'ip_version': ipver,'min_prefix': min_p,'min_usable': min_usable,'candidate_cidr': '','root': '','usable': '','type': 'No candidate found'})
        else:
            for c in candidates:
                plan.append({'hosts': h,'ip_version': ipver,'min_prefix': min_p,'min_usable': min_usable,'candidate_cidr': c['cidr'],'root': c['root'],'usable': c['usable'] if ipver=='IPv4' else c['size'],'type': c['type']})
    return plan

def _min_prefix_for_hosts(ipver: str, hosts: int) -> int:
    if ipver=='IPv4': return min_prefix_for_hosts_ipv4(hosts)
    if hosts<=0: raise ValueError('Host requirement must be positive')
    bits = math.ceil(math.log2(hosts)); return max(0, min(128, 128 - bits))

def _carve_from_block(block: Network, target_prefix: int):
    if target_prefix < block.prefixlen: return None, []
    if target_prefix == block.prefixlen: return block, []
    try: children = list(block.subnets(new_prefix=block.prefixlen + 1))
    except Exception: return None, []
    alloc, leftover = _carve_from_block(children[0], target_prefix)
    if alloc is not None: return alloc, [children[1]] + leftover
    alloc, leftover = _carve_from_block(children[1], target_prefix)
    if alloc is not None: return alloc, [children[0]] + leftover
    return None, []

def allocate_vlsm_by_hosts(root_nets: List[Network], host_reqs: List[int], ipver: str):
    free_per_root = {str(r): [r] for r in root_nets if (ipver=='IPv4' and isinstance(r, IPv4Network)) or (ipver=='IPv6' and isinstance(r, IPv6Network))}
    reqs = []
    for i, h in enumerate(host_reqs):
        pfx = _min_prefix_for_hosts(ipver, h)
        needed = (1 if pfx==32 else (2 if pfx==31 else 2 ** (32 - pfx))) if ipver=='IPv4' else 2 ** (128 - pfx)
        reqs.append({'idx': i+1, 'hosts': h, 'min_prefix': pfx, 'needed': needed})
    reqs.sort(key=lambda x: (-x['needed'], x['idx']))
    allocations = []
    for req in reqs:
        allocated, alloc_root = None, None
        for root_str, free_list in list(free_per_root.items()):
            new_free = []; success = False
            for blk in free_list:
                alloc, leftovers = _carve_from_block(blk, req['min_prefix'])
                if alloc is not None:
                    success = True; allocated = alloc; alloc_root = root_str; new_free.extend(leftovers)
                else: new_free.append(blk)
                if success: pass
            if success: free_per_root[root_str] = new_free; break
        if allocated is None:
            allocations.append({'index': req['idx'],'hosts': req['hosts'],'min_prefix': req['min_prefix'],'allocated': '','root': '','usable_or_size': '','type': '','status': 'Failed','reason': 'Insufficient free space in provided roots'})
        else:
            if ipver=='IPv4': usable_or_size = usable_hosts_ipv4(req['min_prefix']); ntype = classify_ipv4_network(allocated)
            else: usable_or_size = allocated.num_addresses; ntype = classify_ipv6_network(allocated)
            allocations.append({'index': req['idx'],'hosts': req['hosts'],'min_prefix': req['min_prefix'],'allocated': str(allocated),'root': alloc_root,'usable_or_size': usable_or_size,'type': ntype,'status': 'Allocated','reason': ''})
    leftovers = [blk for lst in free_per_root.values() for blk in lst]
    return allocations, leftovers

class PasswordVault:
    """Vault v2: Argon2id/Scrypt KDF + optional Kyber512 hybrid + AES-256-GCM
    Internal Owner Tag: Abhishek Awasthi
    """
    def __init__(self, path: Optional[_Path] = None):
        self.path = path or (_Path.home() / '.aanetsphere_vault.json')
        self.state: Dict = {}
        self._unlocked = False
        self._kek_final: Optional[bytes] = None
        self._dek: Optional[bytes] = None
        self._v2_meta: Optional[Dict] = None
    def exists(self) -> bool: return self.path.exists()
    def create_new(self, master_password: str):
        if not CRYPTO_OK: raise RuntimeError('cryptography library not available')
        salt_kdf = os.urandom(16)
        if ARGON2_OK:
            kdf_method, kdf_params = 'Argon2id', {'time_cost': 3, 'mem_kib': 65536, 'parallelism': 2}
            kek_pwd = derive_key_argon2id(master_password, salt_kdf, length=32, **kdf_params)
        else:
            kdf_method, kdf_params = 'Scrypt', {'n': 2**15, 'r': 8, 'p': 1}
            kek_pwd = derive_key_scrypt(master_password, salt_kdf, length=32, **kdf_params)
        pqc_meta = None
        if KYBER_OK:
            pk, sk = generate_keypair(); ct, kem_key = kyber_encaps(pk)
            nonce_sk = os.urandom(12); sk_enc = AESGCM(kek_pwd).encrypt(nonce_sk, sk, None)
            hkdf_salt = os.urandom(16)
            hkdf = HKDF(algorithm=hashes.SHA3_512(), length=32, salt=hkdf_salt, info=b'AANetSphere-HKDF-PQC')
            kek_final = hkdf.derive(kek_pwd + kem_key)
            pqc_meta = {'kem':'Kyber512','pk': b64e(pk),'ct': b64e(ct),'sk_enc': b64e(sk_enc),'nonce_sk': b64e(nonce_sk),'hkdf_salt': b64e(hkdf_salt)}
        else: kek_final = kek_pwd
        dek = os.urandom(32); nonce_dek = os.urandom(12); dek_wrap = AESGCM(kek_final).encrypt(nonce_dek, dek, None)
        state = {"entries": []}
        nonce_state = os.urandom(12); ct_state = AESGCM(dek).encrypt(nonce_state, json.dumps(state).encode('utf-8'), None)
        obj = {'vault_version': 2,'kdf': kdf_method,'kdf_salt': b64e(salt_kdf),'kdf_params': kdf_params,'nonce_dek': b64e(nonce_dek),'dek_wrap': b64e(dek_wrap),'nonce_state': b64e(nonce_state),'ciphertext_state': b64e(ct_state)}
        if pqc_meta: obj['pqc'] = pqc_meta
        self.path.write_text(json.dumps(obj, indent=2), encoding='utf-8')
        self._unlocked, self.state, self._dek, self._kek_final, self._v2_meta = True, state, dek, kek_final, obj
    def unlock(self, master_password: str) -> bool:
        if not CRYPTO_OK: return False
        try: obj = json.loads(self.path.read_text(encoding='utf-8'))
        except Exception: return False
        try:
            kdf_method = obj['kdf']; salt_kdf = b64d(obj['kdf_salt']); kdf_params = obj.get('kdf_params', {})
            if kdf_method == 'Argon2id' and ARGON2_OK:
                kek_pwd = derive_key_argon2id(master_password, salt_kdf, length=32, **kdf_params)
            elif kdf_method == 'Scrypt':
                n = int(kdf_params.get('n', 2**15)); r = int(kdf_params.get('r', 8)); p = int(kdf_params.get('p', 1))
                kek_pwd = derive_key_scrypt(master_password, salt_kdf, length=32, n=n, r=r, p=p)
            else:
                kek_pwd = derive_key_argon2id(master_password, salt_kdf, length=32) if ARGON2_OK else derive_key_scrypt(master_password, salt_kdf, length=32)
            kek_final = kek_pwd
            pqc = obj.get('pqc')
            if pqc:
                if not KYBER_OK: raise RuntimeError('Kyber required. pip install pqcrypto')
                sk = AESGCM(kek_pwd).decrypt(b64d(pqc['nonce_sk']), b64d(pqc['sk_enc']), None)
                kem_key = kyber_decaps(b64d(pqc['ct']), sk)
                hkdf = HKDF(algorithm=hashes.SHA3_512(), length=32, salt=b64d(pqc['hkdf_salt']), info=b'AANetSphere-HKDF-PQC')
                kek_final = hkdf.derive(kek_pwd + kem_key)
            dek = AESGCM(kek_final).decrypt(b64d(obj['nonce_dek']), b64d(obj['dek_wrap']), None)
            pt = AESGCM(dek).decrypt(b64d(obj['nonce_state']), b64d(obj['ciphertext_state']), None)
            state = json.loads(pt.decode('utf-8'))
            if 'entries' not in state: state = {'entries': []}
            self._unlocked, self._dek, self._kek_final, self.state, self._v2_meta = True, dek, kek_final, state, obj
            return True
        except Exception:
            self._unlocked, self._dek, self._kek_final = False, None, None
            return False
    def _save(self):
        if not (self._unlocked and self._dek and self._v2_meta): raise RuntimeError('Vault is not unlocked')
        nonce_state = os.urandom(12); ct_state = AESGCM(self._dek).encrypt(nonce_state, json.dumps(self.state).encode('utf-8'), None)
        self._v2_meta['nonce_state'] = b64e(nonce_state); self._v2_meta['ciphertext_state'] = b64e(ct_state)
        self.path.write_text(json.dumps(self._v2_meta, indent=2), encoding='utf-8')
    def list_entries(self) -> List[Dict]: return list(self.state.get('entries', [])) if self._unlocked else []
    def add_or_update(self, service: str, username: str, password: str):
        if not self._unlocked: raise RuntimeError('Vault locked')
        now = datetime.datetime.utcnow().isoformat() + 'Z'
        entries = self.state.setdefault('entries', [])
        for e in entries:
            if e['service']==service and e['username']==username:
                e['password']=password; e['updated']=now; self._save(); return
        entries.append({'service':service,'username':username,'password':password,'created':now,'updated':now}); self._save()
    def delete(self, service: str, username: str) -> bool:
        if not self._unlocked: raise RuntimeError('Vault locked')
        entries = self.state.get('entries', [])
        new_entries = [e for e in entries if not (e['service']==service and e['username']==username)]
        if len(new_entries)==len(entries): return False
        self.state['entries']=new_entries; self._save(); return True

def export_to_excel(filename: str, items: List[Dict], overlaps: Optional[List[Dict]]=None, summaries: Optional[Dict[str,List[str]]]=None, dualmap: Optional[List[Dict]]=None, hostplan: Optional[List[Dict]]=None):
    wb = Workbook(); ws = wb.active; ws.title = 'Subnets'
    headers = ['IP Version','Root CIDR','CIDR','Prefix','Total Addresses','Usable Hosts (IPv4)','First IP','Last IP','Type','Overlaps?','Owner','Environment','Purpose','Status']
    ws.append(headers)
    for col_idx, h in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=col_idx); cell.font = Font(bold=True); cell.alignment = Alignment(horizontal='center')
    def net_sort_key(d: Dict):
        root = d.get('root',''); level = d.get('level',0); n = ip_network(d['cidr'], strict=False); na = int(n.network_address)
        return (root, level, na)
    items_sorted = sorted(items, key=net_sort_key)
    levels = {d['cidr']: d['level'] for d in items_sorted}
    parent_children_rows: Dict[str, List[int]] = {}
    for d in items_sorted:
        row = [d['ip_version'], d['root'], d['cidr'], d['prefix'], d['size'], d['usable'], d['first'], d['last'], d['type'], 'Yes' if d.get('overlaps') else 'No', d.get('owner',''), d.get('environment',''), d.get('purpose',''), d.get('status','')]
        ws.append(row)
        current_row_num = ws.max_row
        parent = d.get('parent')
        if parent: parent_children_rows.setdefault(parent, []).append(current_row_num)
    for parent_cidr, rows_list in parent_children_rows.items():
        if not rows_list: continue
        start, end = min(rows_list), max(rows_list)
        if end > start:
            parent_level = levels.get(parent_cidr, 0); outline_level = min(7, parent_level + 1)
            ws.row_dimensions.group(start, end, outline_level=outline_level, hidden=False)
    widths = [12,18,28,8,18,20,36,36,24,12,16,16,22,14]
    for i, w in enumerate(widths, start=1): ws.column_dimensions[chr(64+i)].width = w
    ws.freeze_panes = 'A2'; ws.sheet_properties.outlinePr.summaryBelow = True
    overlaps = overlaps or []
    ws2 = wb.create_sheet(title='Overlaps'); ws2_headers = ['IP Version','CIDR A','Root A','CIDR B','Root B','Overlap First IP','Overlap Last IP']
    ws2.append(ws2_headers)
    for col_idx, h in enumerate(ws2_headers, start=1):
        cell = ws2.cell(row=1, column=col_idx); cell.font = Font(bold=True); cell.alignment = Alignment(horizontal='center')
    for p in overlaps: ws2.append([p['ip_version'], p['cidr_a'], p['root_a'], p['cidr_b'], p['root_b'], p['overlap_first'], p['overlap_last']])
    for i, w in enumerate([12,28,22,28,22,36,36], start=1): ws2.column_dimensions[chr(64+i)].width = w
    ws2.freeze_panes = 'A2'
    summaries = summaries or {'IPv4': [], 'IPv6': []}
    ws3 = wb.create_sheet(title='Summaries'); ws3_headers = ['IP Version', 'Summary CIDR']
    ws3.append(ws3_headers)
    for col_idx, h in enumerate(ws3_headers, start=1):
        cell = ws3.cell(row=1, column=col_idx); cell.font = Font(bold=True); cell.alignment = Alignment(horizontal='center')
    for ver in ['IPv4','IPv6']:
        for cidr in summaries.get(ver, []): ws3.append([ver, cidr])
    ws3.column_dimensions['A'].width = 12; ws3.column_dimensions['B'].width = 40; ws3.freeze_panes = 'A2'
    dualmap = dualmap or []
    ws4 = wb.create_sheet(title='DualStack Mapping'); ws4_headers = ['IPv4 Subnet (leaf)', 'Root', 'Mapped IPv6 Subnet', 'Note']
    ws4.append(ws4_headers)
    for col_idx, h in enumerate(ws4_headers, start=1): ws4.cell(row=1, column=col_idx).font = Font(bold=True)
    for row in dualmap: ws4.append([row['ipv4'], row['root'], row['ipv6_alloc'], row.get('note','')])
    ws4.column_dimensions['A'].width = 28; ws4.column_dimensions['B'].width = 20; ws4.column_dimensions['C'].width = 36; ws4.column_dimensions['D'].width = 16; ws4.freeze_panes = 'A2'
    hostplan = hostplan or []
    if hostplan:
        ws5 = wb.create_sheet(title='Host Planner')
        hp_headers = ['Hosts Req','IP Version','Min Prefix','Min Usable (IPv4)','Candidate CIDR','Root','Usable/Size','Type']
        ws5.append(hp_headers)
        for col_idx, h in enumerate(hp_headers, start=1): ws5.cell(row=1, column=col_idx).font = Font(bold=True)
        for r in hostplan: ws5.append([r.get('hosts'), r.get('ip_version'), r.get('min_prefix'), r.get('min_usable'), r.get('candidate_cidr'), r.get('root'), r.get('usable'), r.get('type')])
        for i, w in enumerate([12,10,10,16,28,20,16,18], start=1): ws5.column_dimensions[chr(64+i)].width = w
        ws5.freeze_panes = 'A2'
    wb.save(filename)

class AANetSphereApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('AANetSphere'); self.geometry('1320x880')
        self.last_items: List[Dict] = []; self.last_overlaps: List[Dict] = []; self.last_summaries: Dict[str,List[str]] = {}
        self.last_dualmap: List[Dict] = []; self.last_hostplan: List[Dict] = []
        self.metadata: Dict[str, Dict[str, str]] = {}
        self.ipv6_base_var = tk.StringVar(value='2001:db8:100::/48'); self.ipv6_target_prefix_var = tk.StringVar(value='64')
        self.host_reqs_var = tk.StringVar(value=''); self.host_planner_ver = tk.StringVar(value='IPv4')
        self.vault = PasswordVault()
        self._build_widgets()
        # Menu bar with Help -> About
        menubar = tk.Menu(self)
        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label='About AANetSphere', command=self._show_about)
        menubar.add_cascade(label='Help', menu=helpmenu)
        self.config(menu=menubar)

    def _build_widgets(self):
        top = ttk.Frame(self); top.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)
        ttk.Label(top, text='Enter CIDRs (one per line or comma-separated)').grid(row=0, column=0, sticky='w')
        self.input_text = tk.Text(top, height=5, width=120); self.input_text.grid(row=1, column=0, columnspan=14, sticky='we', pady=(2,10))
        self.ipver = tk.StringVar(value='Auto')
        ttk.Label(top, text='IP Version:').grid(row=2, column=0, sticky='w')
        for i, v in enumerate(['Auto','IPv4','IPv6']): ttk.Radiobutton(top, text=v, value=v, variable=self.ipver).grid(row=2, column=1+i, sticky='w')
        self.mode = tk.StringVar(value='prefix')
        ttk.Label(top, text='Split Mode:').grid(row=2, column=4, sticky='e')
        ttk.Radiobutton(top, text='By New Prefix', value='prefix', variable=self.mode).grid(row=2, column=5, sticky='w')
        ttk.Radiobutton(top, text='By # Subnets', value='count', variable=self.mode).grid(row=2, column=6, sticky='w')
        mid = ttk.Frame(self); mid.pack(side=tk.TOP, fill=tk.X, padx=10)
        self.prefix_var = tk.StringVar(); self.count_var = tk.StringVar()
        ttk.Label(mid, text='Target New Prefix (optional):').grid(row=0, column=0, sticky='e')
        ttk.Entry(mid, textvariable=self.prefix_var, width=12).grid(row=0, column=1, sticky='w')
        ttk.Label(mid, text='# of Subnets (optional):').grid(row=0, column=2, sticky='e')
        ttk.Entry(mid, textvariable=self.count_var, width=12).grid(row=0, column=3, sticky='w')
        self.include_intermediate = tk.BooleanVar(value=True)
        ttk.Checkbutton(mid, text='Include intermediate splits (grouping)', variable=self.include_intermediate).grid(row=0, column=4, sticky='w', padx=(20,0))
        ds = ttk.Frame(self); ds.pack(side=tk.TOP, fill=tk.X, padx=10, pady=(4,6))
        ttk.Label(ds, text='IPv6 base for Dual-Stack Mapping:').grid(row=0, column=0, sticky='e')
        ttk.Entry(ds, textvariable=self.ipv6_base_var, width=28).grid(row=0, column=1, sticky='w')
        ttk.Label(ds, text='Target IPv6 prefix:').grid(row=0, column=2, sticky='e')
        ttk.Entry(ds, textvariable=self.ipv6_target_prefix_var, width=6).grid(row=0, column=3, sticky='w')
        ttk.Button(ds, text='Manage Metadata', command=self.on_manage_metadata).grid(row=0, column=5, padx=(20,0))
        hp = ttk.Frame(self); hp.pack(side=tk.TOP, fill=tk.X, padx=10, pady=(0,8))
        ttk.Label(hp, text='Host requirements (comma/newline):').grid(row=0, column=0, sticky='e')
        ttk.Entry(hp, textvariable=self.host_reqs_var, width=50).grid(row=0, column=1, sticky='w')
        ttk.Label(hp, text='Planner IP Version:').grid(row=0, column=2, sticky='e', padx=(12,0))
        ttk.Combobox(hp, values=['IPv4','IPv6'], textvariable=self.host_planner_ver, width=8, state='readonly').grid(row=0, column=3, sticky='w')
        act = ttk.Frame(self); act.pack(side=tk.TOP, fill=tk.X, padx=10, pady=8)
        ttk.Button(act, text='Analyze', command=self.on_analyze).pack(side=tk.LEFT)
        ttk.Button(act, text='Overlap Report', command=self.on_overlap_report).pack(side=tk.LEFT, padx=8)
        ttk.Button(act, text='Summarize', command=self.on_summarize).pack(side=tk.LEFT, padx=8)
        ttk.Button(act, text='Dual-Stack Mapping', command=self.on_dualstack).pack(side=tk.LEFT, padx=8)
        ttk.Button(act, text='Host Planner', command=self.on_host_planner).pack(side=tk.LEFT, padx=8)
        ttk.Button(act, text='?', width=3, command=self._show_host_planner_help).pack(side=tk.LEFT, padx=(0,12))
        ttk.Button(act, text='Allocate by Hosts (VLSM)', command=self.on_vlsm_allocate).pack(side=tk.LEFT, padx=8)
        ttk.Button(act, text='?', width=3, command=self._show_vlsm_help).pack(side=tk.LEFT, padx=(0,12))
        ttk.Button(act, text='Password Manager', command=self.on_password_manager).pack(side=tk.LEFT, padx=8)
        ttk.Button(act, text='Export to Excel', command=self.on_export).pack(side=tk.LEFT, padx=8)
        ttk.Button(act, text='Clear', command=self.on_clear).pack(side=tk.LEFT, padx=8)
        cols = ('ip_version','root','cidr','prefix','total','usable','first','last','type','overlaps','owner','environment','purpose','status')
        self.tree = ttk.Treeview(self, columns=cols, show='headings', height=22)
        headings = [('ip_version','IP Version',80), ('root','Root CIDR',160), ('cidr','CIDR',300), ('prefix','Prefix',70), ('total','Total Addresses',130), ('usable','Usable Hosts (IPv4)',160), ('first','First IP',220), ('last','Last IP',220), ('type','Type',140), ('overlaps','Overlaps?',90), ('owner','Owner',120), ('environment','Environment',120), ('purpose','Purpose',160), ('status','Status',100)]
        for cname, label, width in headings: self.tree.heading(cname, text=label); self.tree.column(cname, width=width, anchor='w')
        self.tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        self.status_var = tk.StringVar(value='Ready'); ttk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor='w').pack(side=tk.BOTTOM, fill=tk.X)

    def _show_host_planner_help(self):
        txt = (
            "Host Planner\n\n"
            "Purpose: Find which of your EXISTING subnets can fit N hosts.\n\n"
            "How to use:\n"
            "  1) Click Analyze (optionally split roots first).\n"
            "  2) Enter host counts (comma/newline).\n"
            "  3) Click Host Planner.\n\n"
            "Examples:\n"
            "  • Roots: 10.10.0.0/16, split to /24.\n"
            "    Requirements: 120, 10\n"
            "    Host Planner will list which /24s (or other leaves) can host 120 and 10.\n\n"
            "Notes:\n"
            "  • Does NOT change your subnets; it only suggests candidates.\n"
        )
        win = tk.Toplevel(self); win.title('Help — Host Planner'); win.geometry('600x420')
        txtbox = tk.Text(win, wrap='word'); txtbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        txtbox.insert(tk.END, txt); txtbox.configure(state='disabled')

    def _show_vlsm_help(self):
        txt = (
            "Allocate by Hosts (VLSM)\n\n"
            "Purpose: CREATE NEW subnets sized for each host requirement using VLSM.\n\n"
            "How to use:\n"
            "  1) Provide one or more ROOT CIDRs in the main input.\n"
            "  2) Enter host counts (comma/newline).\n"
            "  3) Choose IPv4/IPv6 in the Planner dropdown.\n"
            "  4) Click Allocate by Hosts (VLSM).\n\n"
            "Example (IPv4):\n"
            "  Root: 10.0.0.0/16\n"
            "  Requirements: 600, 120, 50, 10\n"
            "  Possible result: /22, /25, /26, /28 carved from /16 (largest first).\n\n"
            "Notes:\n"
            "  • This DOES modify your plan conceptually by carving new subnets.\n"
            "  • Output shows success/fail per requirement and remaining space per root.\n"
        )
        win = tk.Toplevel(self); win.title('Help — Allocate by Hosts (VLSM)'); win.geometry('640x460')
        txtbox = tk.Text(win, wrap='word'); txtbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        txtbox.insert(tk.END, txt); txtbox.configure(state='disabled')

    def _show_about(self):
        txt = (
            "AANetSphere\n"
            "Advanced Subnetting, IPAM-lite, and PQC-hardened local password vault.\n\n"
            "Branding:\n"
            "  • Name: AANetSphere\n"
            "  • Tagline: Subnet. Validate. Export. Secure.\n\n"
            "Security (Vault v2):\n"
            "  • AES-256-GCM (content)\n"
            "  • Argon2id (preferred) or Scrypt (KDF)\n"
            "  • Optional Kyber512 hybrid (PQC KEM)\n\n"
            "Hidden Signature:\n"
            "  • Owner: Abhishek Awasthi\n"
            "  • Embedded in internal metadata comments and vault docstrings.\n\n"
            "Made with ❤️ to speed network design and keep secrets safe on-device.\n"
        )
        messagebox.showinfo('About AANetSphere', txt)

    def parse_inputs(self) -> List[Network]:
        raw = self.input_text.get('1.0', tk.END); tokens = [t.strip() for t in raw.replace('\n', ',').split(',') if t.strip()]
        if not tokens: raise ValueError('Please enter at least one CIDR')
        nets: List[Network] = []; ipver = self.ipver.get()
        for t in tokens:
            net = ip_network(t, strict=False)
            if ipver=='IPv4' and isinstance(net, IPv6Network): raise ValueError(f'{t} is IPv6 but IPv4 forced')
            if ipver=='IPv6' and isinstance(net, IPv4Network): raise ValueError(f'{t} is IPv4 but IPv6 forced')
            nets.append(net)
        return nets

    def compute_items(self, nets: List[Network]) -> List[Dict]:
        mode = self.mode.get(); include_intermediate = self.include_intermediate.get()
        prefix_text = self.prefix_var.get().strip(); count_text = self.count_var.get().strip()
        items: List[Dict] = []; total_rows = 0
        def emit_root_only(parent):
            ipver = 'IPv4' if isinstance(parent, IPv4Network) else 'IPv6'; size = count_addresses(parent)
            first_ip = parent.network_address; last_ip = parent.network_address + (parent.num_addresses - 1)
            if isinstance(parent, IPv4Network): usable, ntype = usable_hosts_ipv4(parent.prefixlen), classify_ipv4_network(parent)
            else: usable, ntype = size, classify_ipv6_network(parent)
            root_meta = self.metadata.get(str(parent), {})
            return {'ip_version': ipver,'root': str(parent),'cidr': str(parent),'prefix': parent.prefixlen,'size': int(size),'usable': int(usable),'first': str(first_ip),'last': str(last_ip),'type': ntype,'level': 0,'parent': None,'owner': root_meta.get('owner',''),'environment': root_meta.get('environment',''),'purpose': root_meta.get('purpose',''),'status': root_meta.get('status','')}
        for parent in nets:
            do_split = bool(prefix_text or count_text)
            use_prefix, use_count = None, None
            if do_split:
                if mode=='prefix':
                    if prefix_text: use_prefix = int(prefix_text)
                    elif count_text: use_count = int(count_text)
                elif mode=='count':
                    if count_text: use_count = int(count_text)
                    elif prefix_text: use_prefix = int(prefix_text)
                else:
                    if prefix_text: use_prefix = int(prefix_text)
                    elif count_text: use_count = int(count_text)
            if not do_split: items.append(emit_root_only(parent)); continue
            if use_prefix is not None: target_p, _, _ = analyze_split(parent, target_prefix=use_prefix)
            else: target_p, _, _ = analyze_split(parent, desired_subnets=use_count)
            rows = expand_to_prefix(parent, target_p, include_intermediate=include_intermediate); projected_rows = len(rows)
            if total_rows + projected_rows > MAX_EXPANDED_ROWS: raise ValueError(f'Aborting to prevent huge output: attempting {total_rows + projected_rows} rows (limit {MAX_EXPANDED_ROWS}).\nReduce inputs or choose fewer subnets.')
            root_meta = self.metadata.get(str(parent), {})
            for net, level, parent_net in rows:
                ipver = 'IPv4' if isinstance(net, IPv4Network) else 'IPv6'; size = count_addresses(net)
                first_ip = net.network_address; last_ip = net.network_address + (net.num_addresses - 1)
                if isinstance(net, IPv4Network): usable, ntype = usable_hosts_ipv4(net.prefixlen), classify_ipv4_network(net)
                else: usable, ntype = size, classify_ipv6_network(net)
                nrec = {'ip_version': ipver,'root': str(parent),'cidr': str(net),'prefix': net.prefixlen,'size': int(size),'usable': int(usable),'first': str(first_ip),'last': str(last_ip),'type': ntype,'level': int(level),'parent': str(parent_net) if parent_net is not None else None,'owner': root_meta.get('owner',''),'environment': root_meta.get('environment',''),'purpose': root_meta.get('purpose',''),'status': root_meta.get('status','')}
                items.append(nrec)
            total_rows += projected_rows
        return items

    def analyze_and_detect(self) -> Tuple[List[Dict], List[Dict]]:
        nets = self.parse_inputs(); items = self.compute_items(nets)
        pairs, flags = detect_overlaps(items); [d.update({'overlaps': bool(flags.get(d['cidr']))}) for d in items]
        return items, pairs

    def on_analyze(self):
        try: items, pairs = self.analyze_and_detect()
        except Exception as e: messagebox.showerror('Error', str(e)); return
        self.last_items, self.last_overlaps, self.last_summaries, self.last_dualmap, self.last_hostplan = items, pairs, {}, [], []
        for i in self.tree.get_children(): self.tree.delete(i)
        for d in items:
            indent_cidr = ('    ' * d['level']) + d['cidr']
            vals = (d['ip_version'], d['root'], indent_cidr, d['prefix'], d['size'], d['usable'], d['first'], d['last'], d['type'], 'Yes' if d.get('overlaps') else 'No', d.get('owner',''), d.get('environment',''), d.get('purpose',''), d.get('status',''))
            self.tree.insert('', tk.END, values=vals)
        self.status_var.set(f'Analyzed {len(items)} rows. Overlap pairs: {len(pairs)} (limit {MAX_OVERLAP_PAIRS}).')

    def on_overlap_report(self):
        if not self.last_items:
            try: items, pairs = self.analyze_and_detect(); self.last_items, self.last_overlaps = items, pairs
            except Exception as e: messagebox.showerror('Error', str(e)); return
        pairs = self.last_overlaps
        win = tk.Toplevel(self); win.title('Subnet Overlap Report'); win.geometry('1100x520')
        cols = ('ip_version','cidr_a','root_a','cidr_b','root_b','overlap_first','overlap_last'); tree = ttk.Treeview(win, columns=cols, show='headings', height=18)
        labels = [('ip_version','IP Version',80), ('cidr_a','CIDR A',280), ('root_a','Root A',220), ('cidr_b','CIDR B',280), ('root_b','Root B',220), ('overlap_first','Overlap First IP',200), ('overlap_last','Overlap Last IP',200)]
        for cname, label, width in labels: tree.heading(cname, text=label); tree.column(cname, width=width, anchor='w')
        vsb = ttk.Scrollbar(win, orient='vertical', command=tree.yview); tree.configure(yscroll=vsb.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); vsb.pack(side=tk.RIGHT, fill=tk.Y)
        for p in pairs: tree.insert('', tk.END, values=(p['ip_version'], p['cidr_a'], p['root_a'], p['cidr_b'], p['root_b'], p['overlap_first'], p['overlap_last']))
        ttk.Label(win, text=f'Total overlap pairs: {len(pairs)} (limit {MAX_OVERLAP_PAIRS}).').pack(side=tk.BOTTOM, anchor='w', padx=6, pady=4)

    def on_summarize(self):
        if not self.last_items: messagebox.showerror('Error', 'Run Analyze first.'); return
        use_leaves = tk.BooleanVar(value=True); dlg = tk.Toplevel(self); dlg.title('Summarization Options')
        ttk.Checkbutton(dlg, text='Summarize final subnets only (recommended)', variable=use_leaves).pack(padx=10, pady=10, anchor='w')
        def do_ok():
            summaries = summarize_networks(self.last_items, final_only=use_leaves.get()); self.last_summaries = summaries; dlg.destroy()
            win = tk.Toplevel(self); win.title('Summaries')
            cols = ('version','cidr'); tree = ttk.Treeview(win, columns=cols, show='headings', height=18)
            tree.heading('version', text='IP Version'); tree.heading('cidr', text='Summary CIDR'); tree.column('version', width=100); tree.column('cidr', width=320)
            tree.pack(fill=tk.BOTH, expand=True)
            for ver in ['IPv4','IPv6']:
                for c in summaries.get(ver, []): tree.insert('', tk.END, values=(ver, c))
        ttk.Button(dlg, text='Generate', command=do_ok).pack(padx=10, pady=(0,10))

    def on_dualstack(self):
        if not self.last_items: messagebox.showerror('Error', 'Run Analyze first.'); return
        try: base = self.ipv6_base_var.get().strip(); tgt = int(self.ipv6_target_prefix_var.get().strip()); mapping = dual_stack_map_ipv4_to_ipv6(self.last_items, base, tgt, mode='sequential')
        except Exception as e: messagebox.showerror('Dual-Stack Mapping Error', str(e)); return
        self.last_dualmap = mapping
        win = tk.Toplevel(self); win.title('Dual-Stack Mapping (IPv4 leaves → IPv6 subprefix)')
        cols = ('ipv4','root','ipv6'); tree = ttk.Treeview(win, columns=cols, show='headings', height=18)
        tree.heading('ipv4', text='IPv4 Subnet (leaf)'); tree.heading('root', text='Root'); tree.heading('ipv6', text='Mapped IPv6 Subnet')
        tree.column('ipv4', width=220); tree.column('root', width=200); tree.column('ipv6', width=280)
        tree.pack(fill=tk.BOTH, expand=True)
        for m in mapping: tree.insert('', tk.END, values=(m['ipv4'], m['root'], m['ipv6_alloc']))

    def on_host_planner(self):
        if not self.last_items: messagebox.showerror('Error', 'Run Analyze first.'); return
        raw = self.host_reqs_var.get().strip();
        if not raw: messagebox.showerror('Host Planner', 'Enter host requirements (comma or newline separated).'); return
        tokens = [t.strip() for t in raw.replace('\n', ',').split(',') if t.strip()]
        reqs: List[int] = []
        for t in tokens:
            try: v = int(t); assert v>0; reqs.append(v)
            except Exception: messagebox.showerror('Host Planner', f'Invalid host count: {t}'); return
        try: ver = self.host_planner_ver.get(); plan = compute_host_plan(self.last_items, reqs, ipver=ver)
        except Exception as e: messagebox.showerror('Host Planner Error', str(e)); return
        self.last_hostplan = plan
        win = tk.Toplevel(self); win.title('Host Planner Results'); win.geometry('1100x520')
        cols = ('hosts','ip_version','min_prefix','min_usable','candidate_cidr','root','usable','type'); tree = ttk.Treeview(win, columns=cols, show='headings', height=18)
        labels = [('hosts','Hosts Req',100), ('ip_version','IP Version',90), ('min_prefix','Min Prefix',90), ('min_usable','Min Usable (IPv4)',140), ('candidate_cidr','Candidate CIDR',300), ('root','Root',220), ('usable','Usable/Size',120), ('type','Type',140)]
        for cname, label, width in labels: tree.heading(cname, text=label); tree.column(cname, width=width, anchor='w')
        vsb = ttk.Scrollbar(win, orient='vertical', command=tree.yview); tree.configure(yscroll=vsb.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); vsb.pack(side=tk.RIGHT, fill=tk.Y)
        for r in plan: tree.insert('', tk.END, values=(r.get('hosts'), r.get('ip_version'), r.get('min_prefix'), r.get('min_usable'), r.get('candidate_cidr'), r.get('root'), r.get('usable'), r.get('type')))
        ttk.Label(win, text=f'Total rows: {len(plan)} (limited to {MAX_HOSTPLAN_ROWS_PER_REQ} candidates per requirement).').pack(side=tk.BOTTOM, anchor='w', padx=6, pady=4)

    def on_vlsm_allocate(self):
        try:
            raw = self.input_text.get('1.0', tk.END); tokens = [t.strip() for t in raw.replace('\n', ',').split(',') if t.strip()]
            if not tokens: messagebox.showerror('VLSM Allocation', 'Enter at least one root CIDR.'); return
            roots = [ip_network(t, strict=False) for t in tokens]
        except Exception as e: messagebox.showerror('VLSM Allocation', f'Invalid root CIDR: {e}'); return
        raw_hosts = self.host_reqs_var.get().strip()
        if not raw_hosts: messagebox.showerror('VLSM Allocation', 'Enter host requirements (comma or newline separated).'); return
        toks = [t.strip() for t in raw_hosts.replace('\n', ',').split(',') if t.strip()]
        host_reqs: List[int] = []
        for t in toks:
            try: v = int(t); assert v>0; host_reqs.append(v)
            except Exception: messagebox.showerror('VLSM Allocation', f'Invalid host count: {t}'); return
        ver = self.host_planner_ver.get()
        try: allocs, leftovers = allocate_vlsm_by_hosts(roots, host_reqs, ver)
        except Exception as e: messagebox.showerror('VLSM Allocation Error', str(e)); return
        self.last_hostplan = []
        for a in allocs:
            self.last_hostplan.append({'hosts': a['hosts'], 'ip_version': ver, 'min_prefix': a['min_prefix'], 'min_usable': usable_hosts_ipv4(a['min_prefix']) if ver=='IPv4' else 2 ** (128 - a['min_prefix']), 'candidate_cidr': a['allocated'], 'root': a['root'], 'usable': a['usable_or_size'], 'type': a['type']})
        win = tk.Toplevel(self); win.title('VLSM Allocation Results (Host-driven)'); win.geometry('1100x560')
        cols = ('index','hosts','min_prefix','allocated','root','usable_or_size','type','status','reason'); tree = ttk.Treeview(win, columns=cols, show='headings', height=20)
        labels = [('index','Idx',60), ('hosts','Hosts',80), ('min_prefix','Min Prefix',100), ('allocated','Allocated CIDR',280), ('root','Root',220), ('usable_or_size','Usable/Size',120), ('type','Type',140), ('status','Status',100), ('reason','Reason',220)]
        for cname, label, width in labels: tree.heading(cname, text=label); tree.column(cname, width=width, anchor='w')
        vsb = ttk.Scrollbar(win, orient='vertical', command=tree.yview); tree.configure(yscroll=vsb.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); vsb.pack(side=tk.RIGHT, fill=tk.Y)
        for a in allocs: tree.insert('', tk.END, values=(a['index'], a['hosts'], a['min_prefix'], a['allocated'], a['root'], a['usable_or_size'], a['type'], a['status'], a['reason']))
        ttk.Label(win, text=f'Allocations: {sum(1 for a in allocs if a["status"]=="Allocated")}, Failed: {sum(1 for a in allocs if a["status"]!="Allocated")}.').pack(side=tk.BOTTOM, anchor='w', padx=6, pady=4)

    def on_password_manager(self):
        if not CRYPTO_OK: messagebox.showerror('Password Manager', 'Requires cryptography.\n\nInstall with:\n  pip install cryptography'); return
        win = tk.Toplevel(self)
        pqc_label = 'Kyber: Available' if KYBER_OK else 'Kyber: Not installed (pip install pqcrypto)'
        kdf_label = 'Argon2id preferred' if ARGON2_OK else 'Argon2id not installed (pip install argon2-cffi) — using Scrypt'
        win.title(f'AANetSphere — Password Manager (AES-256-GCM, PQC Hybrid) | {pqc_label} | {kdf_label}')
        win.geometry('920x600')
        frm_top = ttk.LabelFrame(win, text='Vault'); frm_top.pack(side=tk.TOP, fill=tk.X, padx=10, pady=8)
        def do_create():
            if self.vault.exists():
                if not messagebox.askyesno('Create', 'Vault already exists. Overwrite? This will ERASE existing entries.'): return
            pw1 = simpledialog.askstring('Set Master Password', 'Enter new master password:', show='*', parent=win)
            if not pw1: return
            pw2 = simpledialog.askstring('Confirm Master Password', 'Re-enter master password:', show='*', parent=win)
            if pw1 != pw2: messagebox.showerror('Create', 'Passwords do not match.'); return
            try:
                self.vault.create_new(pw1); messagebox.showinfo('Create', f'Vault created at {self.vault.path}\nMode: v2 | KDF: {"Argon2id" if ARGON2_OK else "Scrypt"} | PQC: {"Kyber512" if KYBER_OK else "off"}'); refresh_entries()
            except Exception as e: messagebox.showerror('Create', str(e))
        def do_unlock():
            if not self.vault.exists(): messagebox.showerror('Unlock', 'Vault not found. Create it first.'); return
            pw = simpledialog.askstring('Unlock Vault', 'Enter master password:', show='*', parent=win)
            if not pw: return
            ok = self.vault.unlock(pw)
            if ok: messagebox.showinfo('Unlock', 'Vault unlocked.'); refresh_entries()
            else: messagebox.showerror('Unlock', 'Incorrect password, missing PQC dependencies, or vault format mismatch.')
        ttk.Button(frm_top, text='Create New Vault', command=do_create).pack(side=tk.LEFT, padx=6, pady=6)
        ttk.Button(frm_top, text='Unlock Existing Vault', command=do_unlock).pack(side=tk.LEFT, padx=6, pady=6)
        ttk.Label(frm_top, text=f'Vault path: {self.vault.path}').pack(side=tk.LEFT, padx=16)
        frm_gen = ttk.LabelFrame(win, text='Generate Password'); frm_gen.pack(side=tk.TOP, fill=tk.X, padx=10, pady=6)
        length_var = tk.IntVar(value=20); use_upper = tk.BooleanVar(value=True); use_lower = tk.BooleanVar(value=True); use_digits = tk.BooleanVar(value=True); use_symbols = tk.BooleanVar(value=True); avoid_amb = tk.BooleanVar(value=True)
        ttk.Label(frm_gen, text='Length:').grid(row=0, column=0, sticky='e'); ttk.Spinbox(frm_gen, from_=8, to=128, textvariable=length_var, width=6).grid(row=0, column=1, sticky='w')
        ttk.Checkbutton(frm_gen, text='Uppercase', variable=use_upper).grid(row=0, column=2, sticky='w', padx=(12,0))
        ttk.Checkbutton(frm_gen, text='Lowercase', variable=use_lower).grid(row=0, column=3, sticky='w')
        ttk.Checkbutton(frm_gen, text='Digits', variable=use_digits).grid(row=0, column=4, sticky='w')
        ttk.Checkbutton(frm_gen, text='Symbols', variable=use_symbols).grid(row=0, column=5, sticky='w')
        ttk.Checkbutton(frm_gen, text='Avoid ambiguous (O0Il1)', variable=avoid_amb).grid(row=0, column=6, sticky='w')
        gen_out = tk.StringVar(value=''); ttk.Entry(frm_gen, textvariable=gen_out, width=90).grid(row=1, column=0, columnspan=6, sticky='we', pady=6)
        def do_copy(): win.clipboard_clear(); win.clipboard_append(gen_out.get()); win.update(); self.status_var.set('Password copied to clipboard')
        ttk.Button(frm_gen, text='Copy', command=do_copy).grid(row=1, column=6, sticky='w')
        def generate_pw():
            upper = 'ABCDEFGHJKMNPQRSTUVWXYZ' if avoid_amb.get() else 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            lower = 'abcdefghjkmnpqrstuvwxyz' if avoid_amb.get() else 'abcdefghijklmnopqrstuvwxyz'
            digits = '23456789' if avoid_amb.get() else '0123456789'
            symbols = '!@#$%^&*()-_=+[]{};:,.<>?/\\'
            pool = ''
            if use_upper.get(): pool += upper
            if use_lower.get(): pool += lower
            if use_digits.get(): pool += digits
            if use_symbols.get(): pool += symbols
            if not pool: messagebox.showerror('Generate', 'Select at least one character set.'); return
            n = max(8, int(length_var.get()))
            parts = []
            if use_upper.get(): parts.append(secrets.choice(upper))
            if use_lower.get(): parts.append(secrets.choice(lower))
            if use_digits.get(): parts.append(secrets.choice(digits))
            if use_symbols.get(): parts.append(secrets.choice(symbols))
            while len(parts) < n: parts.append(secrets.choice(pool))
            secrets.SystemRandom().shuffle(parts); gen_out.set(''.join(parts))
        ttk.Button(frm_gen, text='Generate', command=generate_pw).grid(row=0, column=7, padx=8)
        frm_entries = ttk.LabelFrame(win, text='Entries'); frm_entries.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=6)
        cols = ('service','username','updated'); tree = ttk.Treeview(frm_entries, columns=cols, show='headings', height=12)
        tree.heading('service', text='Service'); tree.heading('username', text='Username'); tree.heading('updated', text='Updated (UTC)')
        tree.column('service', width=260); tree.column('username', width=240); tree.column('updated', width=220)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); vsb = ttk.Scrollbar(frm_entries, orient='vertical', command=tree.yview); tree.configure(yscroll=vsb.set); vsb.pack(side=tk.RIGHT, fill=tk.Y)
        frm_btns = ttk.Frame(win); frm_btns.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=6)
        service_var = tk.StringVar(); user_var = tk.StringVar(); pw_var = tk.StringVar()
        ttk.Label(frm_btns, text='Service:').grid(row=0, column=0, sticky='e'); ttk.Entry(frm_btns, textvariable=service_var, width=30).grid(row=0, column=1, sticky='w')
        ttk.Label(frm_btns, text='Username:').grid(row=0, column=2, sticky='e'); ttk.Entry(frm_btns, textvariable=user_var, width=28).grid(row=0, column=3, sticky='w')
        ttk.Label(frm_btns, text='Password:').grid(row=0, column=4, sticky='e'); ttk.Entry(frm_btns, textvariable=pw_var, width=30, show='*').grid(row=0, column=5, sticky='w')
        ttk.Button(frm_btns, text='Use Generated', command=lambda: pw_var.set(gen_out.get())).grid(row=0, column=6, padx=6)
        ttk.Button(frm_btns, text='Add/Update', command=lambda: self._add_update_entry(service_var, user_var, pw_var, tree, win)).grid(row=0, column=7, padx=6)
        ttk.Button(frm_btns, text='Delete', command=lambda: self._delete_entry(tree, win)).grid(row=0, column=8, padx=6)
        ttk.Button(frm_btns, text='Copy Username', command=lambda: self._copy_username(tree)).grid(row=1, column=1, pady=6)
        ttk.Button(frm_btns, text='Copy Password', command=lambda: self._copy_password(tree)).grid(row=1, column=2, pady=6)
        def refresh_entries():
            for i in tree.get_children(): tree.delete(i)
            if not self.vault._unlocked: return
            for e in self.vault.list_entries(): tree.insert('', tk.END, values=(e['service'], e['username'], e.get('updated','')))
        self._pm_refresh = refresh_entries; refresh_entries()

    def _add_update_entry(self, service_var, user_var, pw_var, tree, win):
        try:
            if not self.vault._unlocked: messagebox.showerror('Vault', 'Unlock the vault first.'); return
            s = service_var.get().strip(); u = user_var.get().strip(); p = pw_var.get()
            if not s or not u or not p: messagebox.showerror('Entry', 'Service, Username, and Password are required.'); return
            self.vault.add_or_update(s, u, p); messagebox.showinfo('Entry', 'Saved.'); self._pm_refresh()
        except Exception as e: messagebox.showerror('Entry', str(e))

    def _delete_entry(self, tree, win):
        if not self.vault._unlocked: messagebox.showerror('Vault', 'Unlock the vault first.'); return
        sel = tree.selection();
        if not sel: messagebox.showerror('Delete', 'Select an entry.'); return
        s, u = tree.item(sel[0], 'values')[:2]
        if messagebox.askyesno('Delete', f'Delete entry for {s} / {u}?'):
            ok = self.vault.delete(s, u)
            if ok: messagebox.showinfo('Delete', 'Deleted.'); self._pm_refresh()
            else: messagebox.showerror('Delete', 'Entry not found.')

    def _copy_username(self, tree):
        sel = tree.selection();
        if not sel: return
        vals = tree.item(sel[0], 'values')
        self.clipboard_clear(); self.clipboard_append(vals[1]); self.update(); self.status_var.set('Username copied to clipboard')

    def _copy_password(self, tree):
        if not self.vault._unlocked: messagebox.showerror('Vault', 'Unlock the vault first.'); return
        sel = tree.selection();
        if not sel: return
        s, u = tree.item(sel[0], 'values')[:2]
        for e in self.vault.list_entries():
            if e['service']==s and e['username']==u:
                self.clipboard_clear(); self.clipboard_append(e['password']); self.update(); self.status_var.set('Password copied to clipboard'); return

    def on_export(self):
        if not self.last_items:
            try: items, pairs = self.analyze_and_detect(); self.last_items, self.last_overlaps = items, pairs
            except Exception as e: messagebox.showerror('Error', str(e)); return
        filename = filedialog.asksaveasfilename(defaultextension='.xlsx', filetypes=[('Excel Workbook','*.xlsx')], title='Save Excel')
        if not filename: return
        try: export_to_excel(filename, self.last_items, self.last_overlaps, self.last_summaries, self.last_dualmap, self.last_hostplan)
        except Exception as e: messagebox.showerror('Export Error', str(e)); return
        messagebox.showinfo('Export', f'Exported {len(self.last_items)} rows, {len(self.last_overlaps)} overlap pairs, {sum(len(v) for v in self.last_summaries.values())} summaries, {len(self.last_dualmap)} dual-stack mappings, and {len(self.last_hostplan)} host-plan rows to {filename}')

    def on_clear(self):
        self.input_text.delete('1.0', tk.END)
        self.host_reqs_var.set('')
        self.ipv6_base_var.set('2001:db8:100::/48'); self.ipv6_target_prefix_var.set('64')
        for i in self.tree.get_children(): self.tree.delete(i)
        self.last_items = []; self.last_overlaps = []; self.last_summaries = {}; self.last_dualmap = []; self.last_hostplan = []
        self.metadata = {}
        try:
            if hasattr(self, 'vault') and self.vault is not None:
                self.vault._unlocked = False; self.vault.state = {}; self.vault._dek = None; self.vault._kek_final = None; self.vault._v2_meta = None
        except Exception: pass
        self.status_var.set('Cleared. Ready')

    def on_manage_metadata(self):
        dlg = tk.Toplevel(self); dlg.title('Manage Metadata (per Root CIDR)'); dlg.geometry('760x420')
        try: nets = self.parse_inputs(); roots = [str(n) for n in nets]
        except Exception: roots = list(self.metadata.keys())
        root_var = tk.StringVar(value=roots[0] if roots else '')
        ttk.Label(dlg, text='Root CIDR:').grid(row=0, column=0, sticky='e', padx=6, pady=6)
        cmb = ttk.Combobox(dlg, textvariable=root_var, values=roots, width=28); cmb.grid(row=0, column=1, sticky='w', pady=6)
        owner_var = tk.StringVar(); env_var = tk.StringVar(); purpose_var = tk.StringVar(); status_var = tk.StringVar()
        def load_fields():
            meta = self.metadata.get(root_var.get(), {})
            owner_var.set(meta.get('owner','')); env_var.set(meta.get('environment','')); purpose_var.set(meta.get('purpose','')); status_var.set(meta.get('status',''))
        ttk.Button(dlg, text='Load', command=load_fields).grid(row=0, column=2, padx=6)
        ttk.Label(dlg, text='Owner:').grid(row=1, column=0, sticky='e', padx=6, pady=4); ttk.Entry(dlg, textvariable=owner_var, width=30).grid(row=1, column=1, sticky='w')
        ttk.Label(dlg, text='Environment:').grid(row=2, column=0, sticky='e', padx=6, pady=4); ttk.Entry(dlg, textvariable=env_var, width=30).grid(row=2, column=1, sticky='w')
        ttk.Label(dlg, text='Purpose:').grid(row=3, column=0, sticky='e', padx=6, pady=4); ttk.Entry(dlg, textvariable=purpose_var, width=46).grid(row=3, column=1, sticky='w')
        ttk.Label(dlg, text='Status:').grid(row=4, column=0, sticky='e', padx=6, pady=4); ttk.Entry(dlg, textvariable=status_var, width=20).grid(row=4, column=1, sticky='w')
        def save_meta():
            root = root_var.get().strip()
            if not root: messagebox.showerror('Error','Select or type a root CIDR'); return
            try: ip_network(root, strict=False)
            except Exception as e: messagebox.showerror('Error', f'Invalid root CIDR: {e}'); return
            self.metadata[root] = {'owner': owner_var.get().strip(), 'environment': env_var.get().strip(), 'purpose': purpose_var.get().strip(), 'status': status_var.get().strip()}
            messagebox.showinfo('Saved', f'Metadata saved for {root}')
        def export_meta():
            if not self.metadata: messagebox.showerror('Error','No metadata to export'); return
            filename = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON','*.json')], title='Export Metadata JSON')
            if not filename: return
            with open(filename, 'w', encoding='utf-8') as f: json.dump(self.metadata, f, indent=2)
            messagebox.showinfo('Exported', f'Metadata exported to {filename}')
        def import_meta():
            filename = filedialog.askopenfilename(filetypes=[('JSON','*.json')], title='Import Metadata JSON')
            if not filename: return
            try:
                with open(filename, 'r', encoding='utf-8') as f: data = json.load(f)
                for k, v in data.items(): ip_network(k, strict=False); assert isinstance(v, dict)
                self.metadata.update(data); messagebox.showinfo('Imported', f'Metadata imported from {filename}')
            except Exception as e: messagebox.showerror('Import Error', str(e))
        btns = ttk.Frame(dlg); btns.grid(row=5, column=0, columnspan=3, pady=8)
        ttk.Button(btns, text='Save/Update', command=save_meta).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text='Export JSON', command=export_meta).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text='Import JSON', command=import_meta).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text='Close', command=dlg.destroy).pack(side=tk.LEFT, padx=6)

if __name__ == '__main__':
    app = AANetSphereApp(); app.mainloop()
