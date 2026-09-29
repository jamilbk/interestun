#!/usr/bin/env python3
"""Index the saved macOS 26A428 NE disassembly without invoking networking APIs.

Loads NetworkExtension into this process solely to read shared-cache stub bytes
and symbol metadata. No network objects, sockets, interfaces, XPC requests, or
channels are created. This is a build-pinned research tool, not a general
arm64 disassembler. Generated Apple disassembly remains under ignored target/.
"""
import ctypes as C, re, struct, json
import hashlib
import platform
import subprocess

if platform.system() != 'Darwin' or platform.machine() != 'arm64':
 raise SystemExit('Requires the audited Apple Silicon Mac')
if subprocess.check_output(['sw_vers', '-buildVersion'], text=True).strip() != '26A428':
 raise SystemExit('Refusing stale shared-cache addresses: requires build 26A428')
from pathlib import Path
root=Path('target/apple-path')
out=root/'ne-full-audit-20260929'
out.mkdir(parents=True, exist_ok=True)
source = root/'networkextension-disassembly.txt'
expected = '93ea4cd4ab846b874b23bde8ff07edc0d7bd25a76be71f890872f36671aea908'
if hashlib.sha256(source.read_bytes()).hexdigest() != expected:
 raise SystemExit('Disassembly differs from the audited snapshot; re-audit addresses first')
ne=C.CDLL('/System/Library/Frameworks/NetworkExtension.framework/NetworkExtension')
slide=C.cast(ne.NEVirtualInterfaceCreate,C.c_void_p).value-0x1966d3c30
class DlInfo(C.Structure):
 _fields_=[('fname',C.c_char_p),('base',C.c_void_p),('sname',C.c_char_p),('saddr',C.c_void_p)]
lib=C.CDLL(None); lib.dladdr.argtypes=[C.c_void_p,C.POINTER(DlInfo)]
def resolve(a):
 # Decode the installed arm64 shared-cache selector and import stub patterns.
 words=struct.unpack('<4I',C.string_at(a+slide,16))
 w,v=words[:2]
 if w&0x9f000000!=0x90000000 or v&0xffc00000!=0x91000000:return None
 reg=w&31
 if (v&31)!=reg or ((v>>5)&31)!=reg:return None
 imm=((w>>5)&0x7ffff)<<2 | ((w>>29)&3)
 if imm&(1<<20):imm-=1<<21
 addr=((a+slide)&~4095)+(imm<<12)+((v>>10)&4095)
 if reg==1:
  return 'objc:'+C.string_at(addr).decode('utf-8')
 if reg==17 and words[2]==0xf9400230:
  ptr=C.c_uint64.from_address(addr).value & 0x7fffffffff
  info=DlInfo()
  if lib.dladdr(ptr,C.byref(info)) and info.sname:return info.sname.decode()
 return None
src=(root/'networkextension-disassembly.txt').read_text()
addrs=sorted({int(x,16) for x in re.findall(r'\b(?:bl|b)\s+(0x198[0-9a-f]+)',src)})
resolved={hex(a):resolve(a) for a in addrs}
(out/'stub-symbols.json').write_text(json.dumps(resolved,indent=2))
lines=[]; funcs=[]; current=None
for l in src.splitlines():
 if l and not l.startswith(('0x',' ','(','/')) and l.endswith(':'):
  current={'name':l[:-1],'calls':[]};funcs.append(current)
 m=re.search(r'\b(?:bl|b)\s+(0x198[0-9a-f]+)',l)
 if m and resolved.get(m[1]):l+=' ; '+resolved[m[1]]
 if current and re.search(r'\b(?:bl|b)\s+',l):current['calls'].append(l)
 lines.append(l)
(out/'annotated.txt').write_text('\n'.join(lines)+'\n')
(out/'functions.json').write_text(json.dumps(funcs,indent=2))

pattern = re.compile(
 r'NEVirtualInterfaceCreate|NEVirtualInterface.*(?:Channel|Nexus)|'
 r'channelCount:|enableWithChannelCount:|shouldCreateKernelChannel:|'
 r'os_channel_create|nw_channel_create|nw_nexus_create|'
 r'NEHelper.*(?:Socket|Interface)|; setsockopt|; mmap')
sinks = [{'name': f['name'], 'calls': [c for c in f['calls'] if pattern.search(c)]}
         for f in funcs if any(pattern.search(c) for c in f['calls'])]
(out/'creation-callers.json').write_text(json.dumps(sinks, indent=2)+'\n')
summary = {'os_build': '26A428', 'disassembly_sha256': expected,
           'named_code_entries': len(funcs), 'external_stub_targets': len(addrs),
           'resolved_stub_targets': sum(v is not None for v in resolved.values()),
           'candidate_callers': len(sinks),
           'limitations': 'Indexes direct branches; does not prove reachability or '
                          'resolve arbitrary indirect calls or external-image callers.'}
(out/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
print(json.dumps(summary, indent=2))
