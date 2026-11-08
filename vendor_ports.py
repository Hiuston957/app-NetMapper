"""Offline CSV-driven vendor-specific TCP checks."""
import csv
from functools import lru_cache
from pathlib import Path
PATH=Path(__file__).with_name('vendor_ports.csv')
@lru_cache(maxsize=1)
def load():
    with PATH.open(encoding='utf-8',newline='') as f:return list(csv.DictReader(f))
def matching(vendor_name):
    if not vendor_name or any(t in vendor_name.lower() for t in ('nieznany','brak lokalnej','losowy','multicast')):return []
    name=vendor_name.casefold();result=[]
    for r in load():
        aliases=[a.strip().casefold() for a in r['aliases'].split(';')]+[r['vendor'].casefold()]
        if any(len(a)>=4 and a in name for a in aliases) and r['protocol']=='TCP':result.append(r)
    return result
