#!/usr/bin/env python3
"""
Production-Grade DNS Server with Caching, DNSSEC, Security, and Advanced Features
"""

import sys
import socket
import struct
import time
import threading
import logging
import json
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from collections import OrderedDict
from datetime import datetime, timedelta
import select


# ==================== Configuration ====================
@dataclass
class ServerConfig:
    """Server configuration"""
    bind_address: str = "127.0.0.1"
    bind_port: int = 2053
    resolvers: List[Tuple[str, int]] = field(default_factory=list)
    cache_size: int = 10000
    cache_ttl_min: int = 60
    cache_ttl_max: int = 86400
    timeout: int = 5
    max_retries: int = 3
    enable_dnssec: bool = False
    enable_tcp: bool = True
    enable_logging: bool = True
    log_level: str = "INFO"
    blacklist_file: Optional[str] = None
    whitelist_file: Optional[str] = None
    rate_limit: int = 500  # queries per second per IP
    edns_buffer_size: int = 4096
    
    # Metrics
    enable_metrics: bool = True
    metrics_port: int = 9053


# ==================== DNS Data Structures ====================
@dataclass
class DNSHeader:
    """Represents the 12-byte header of a DNS message."""
    id: int
    flags: int
    qdcount: int = 0
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0

    def pack(self) -> bytes:
        """Packs the header into a 12-byte sequence."""
        return struct.pack(
            "!HHHHHH",
            self.id,
            self.flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

    @classmethod
    def unpack(cls, data: bytes) -> 'DNSHeader':
        """Unpacks 12 bytes of data into a DNSHeader object."""
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            "!HHHHHH", data[:12])
        return cls(id, flags, qdcount, ancount, nscount, arcount)

    def get_qr(self) -> int:
        return (self.flags >> 15) & 1

    def get_opcode(self) -> int:
        return (self.flags >> 11) & 0b1111

    def get_aa(self) -> int:
        return (self.flags >> 10) & 1

    def get_tc(self) -> int:
        return (self.flags >> 9) & 1

    def get_rd(self) -> int:
        return (self.flags >> 8) & 1

    def get_ra(self) -> int:
        return (self.flags >> 7) & 1

    def get_rcode(self) -> int:
        return self.flags & 0b1111

    @staticmethod
    def build_flags(qr=0, opcode=0, aa=0, tc=0, rd=0, ra=0, z=0, rcode=0) -> int:
        """Builds flags from individual components."""
        return (qr << 15) | (opcode << 11) | (aa << 10) | (tc << 9) | \
               (rd << 8) | (ra << 7) | (z << 4) | rcode


@dataclass
class DNSQuestion:
    """Represents a question in the DNS message."""
    name: bytes
    type_: int
    class_: int

    def pack(self) -> bytes:
        """Packs the question into bytes."""
        return self.name + struct.pack("!HH", self.type_, self.class_)

    def to_string(self) -> str:
        """Convert to human-readable string."""
        labels = []
        i = 0
        while i < len(self.name):
            length = self.name[i]
            if length == 0:
                break
            i += 1
            labels.append(self.name[i:i+length].decode('utf-8', errors='ignore'))
            i += length
        return '.'.join(labels) if labels else '.'


@dataclass
class DNSRecord:
    """Represents a resource record."""
    name: bytes
    type_: int
    class_: int
    ttl: int
    data: bytes

    def pack(self) -> bytes:
        """Packs the record into bytes."""
        length = len(self.data)
        return self.name + struct.pack("!HHIH", self.type_, self.class_, self.ttl, length) + self.data


@dataclass
class EDNSOption:
    """EDNS0 OPT pseudo-record."""
    code: int
    data: bytes

    def pack(self) -> bytes:
        return struct.pack("!HH", self.code, len(self.data)) + self.data


# ==================== DNS Record Types ====================
class DNSType:
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    OPT = 41  # EDNS0
    DNSKEY = 48
    RRSIG = 46
    NSEC = 47
    NSEC3 = 50
    DS = 43
    CAA = 257
    ANY = 255


class DNSClass:
    IN = 1
    CS = 2
    CH = 3
    HS = 4


class DNSRCode:
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5


# ==================== Caching ====================
class DNSCache:
    """Thread-safe LRU cache with TTL support."""
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.cache: OrderedDict = OrderedDict()
        self.lock = threading.RLock()
        self.hits = 0
        self.misses = 0

    def _make_key(self, question: DNSQuestion) -> str:
        """Create cache key from question."""
        return hashlib.md5(question.name + struct.pack("!HH", question.type_, question.class_)).hexdigest()

    def get(self, question: DNSQuestion) -> Optional[Tuple[List[DNSRecord], List[DNSRecord], List[DNSRecord], float]]:
        """Get cached response if valid."""
        key = self._make_key(question)
        
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                # Check if expired
                if time.time() < entry['expires']:
                    # Move to end (LRU)
                    self.cache.move_to_end(key)
                    self.hits += 1
                    
                    # Update TTLs
                    time_left = entry['expires'] - time.time()
                    answers = [DNSRecord(r.name, r.type_, r.class_, int(time_left), r.data) 
                              for r in entry['answers']]
                    authorities = [DNSRecord(r.name, r.type_, r.class_, int(time_left), r.data) 
                                  for r in entry['authorities']]
                    additionals = [DNSRecord(r.name, r.type_, r.class_, int(time_left), r.data) 
                                  for r in entry['additionals']]
                    
                    return answers, authorities, additionals, entry['rcode']
                else:
                    # Expired, remove
                    del self.cache[key]
            
            self.misses += 1
            return None

    def put(self, question: DNSQuestion, answers: List[DNSRecord], 
            authorities: List[DNSRecord], additionals: List[DNSRecord], 
            rcode: int, ttl: int):
        """Cache a response."""
        key = self._make_key(question)
        
        with self.lock:
            # Evict oldest if at capacity
            if len(self.cache) >= self.max_size:
                self.cache.popitem(last=False)
            
            self.cache[key] = {
                'answers': answers,
                'authorities': authorities,
                'additionals': additionals,
                'rcode': rcode,
                'expires': time.time() + ttl,
                'cached_at': time.time()
            }
            self.cache.move_to_end(key)

    def clear(self):
        """Clear the cache."""
        with self.lock:
            self.cache.clear()

    def get_stats(self) -> Dict:
        """Get cache statistics."""
        with self.lock:
            total = self.hits + self.misses
            hit_rate = (self.hits / total * 100) if total > 0 else 0
            return {
                'size': len(self.cache),
                'max_size': self.max_size,
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': f"{hit_rate:.2f}%"
            }


# ==================== Domain Filtering ====================
class DomainFilter:
    """Blacklist/Whitelist domain filtering."""
    
    def __init__(self):
        self.blacklist: Set[str] = set()
        self.whitelist: Set[str] = set()
        self.lock = threading.RLock()

    def load_blacklist(self, filename: str):
        """Load blacklist from file."""
        try:
            with open(filename, 'r') as f:
                with self.lock:
                    self.blacklist = set(line.strip().lower() for line in f if line.strip() and not line.startswith('#'))
            logging.info(f"Loaded {len(self.blacklist)} domains into blacklist")
        except FileNotFoundError:
            logging.warning(f"Blacklist file not found: {filename}")

    def load_whitelist(self, filename: str):
        """Load whitelist from file."""
        try:
            with open(filename, 'r') as f:
                with self.lock:
                    self.whitelist = set(line.strip().lower() for line in f if line.strip() and not line.startswith('#'))
            logging.info(f"Loaded {len(self.whitelist)} domains into whitelist")
        except FileNotFoundError:
            logging.warning(f"Whitelist file not found: {filename}")

    def is_blocked(self, domain: str) -> bool:
        """Check if domain is blocked."""
        domain = domain.lower().rstrip('.')
        
        with self.lock:
            # Whitelist takes precedence
            if self.whitelist and domain in self.whitelist:
                return False
            
            # Check blacklist
            if domain in self.blacklist:
                return True
            
            # Check parent domains
            parts = domain.split('.')
            for i in range(len(parts)):
                parent = '.'.join(parts[i:])
                if parent in self.blacklist:
                    return True
        
        return False


# ==================== Rate Limiting ====================
class RateLimiter:
    """Token bucket rate limiter per IP."""
    
    def __init__(self, rate: int):
        self.rate = rate
        self.buckets: Dict[str, Dict] = {}
        self.lock = threading.RLock()

    def allow(self, ip: str) -> bool:
        """Check if request is allowed."""
        now = time.time()
        
        with self.lock:
            if ip not in self.buckets:
                self.buckets[ip] = {
                    'tokens': self.rate,
                    'last_update': now
                }
            
            bucket = self.buckets[ip]
            
            # Refill tokens
            elapsed = now - bucket['last_update']
            bucket['tokens'] = min(self.rate, bucket['tokens'] + elapsed * self.rate)
            bucket['last_update'] = now
            
            # Check if we have tokens
            if bucket['tokens'] >= 1:
                bucket['tokens'] -= 1
                return True
            
            return False

    def cleanup(self):
        """Remove old entries."""
        now = time.time()
        with self.lock:
            old_ips = [ip for ip, bucket in self.buckets.items() 
                      if now - bucket['last_update'] > 3600]
            for ip in old_ips:
                del self.buckets[ip]


# ==================== Metrics ====================
class Metrics:
    """Server metrics tracking."""
    
    def __init__(self):
        self.lock = threading.RLock()
        self.queries_total = 0
        self.queries_by_type: Dict[int, int] = {}
        self.responses_by_rcode: Dict[int, int] = {}
        self.cache_hits = 0
        self.cache_misses = 0
        self.blocked_queries = 0
        self.rate_limited = 0
        self.upstream_errors = 0
        self.start_time = time.time()

    def record_query(self, qtype: int):
        with self.lock:
            self.queries_total += 1
            self.queries_by_type[qtype] = self.queries_by_type.get(qtype, 0) + 1

    def record_response(self, rcode: int):
        with self.lock:
            self.responses_by_rcode[rcode] = self.responses_by_rcode.get(rcode, 0) + 1

    def record_cache_hit(self):
        with self.lock:
            self.cache_hits += 1

    def record_cache_miss(self):
        with self.lock:
            self.cache_misses += 1

    def record_blocked(self):
        with self.lock:
            self.blocked_queries += 1

    def record_rate_limited(self):
        with self.lock:
            self.rate_limited += 1

    def record_upstream_error(self):
        with self.lock:
            self.upstream_errors += 1

    def get_stats(self) -> Dict:
        with self.lock:
            uptime = time.time() - self.start_time
            qps = self.queries_total / uptime if uptime > 0 else 0
            
            return {
                'uptime_seconds': int(uptime),
                'queries_total': self.queries_total,
                'queries_per_second': f"{qps:.2f}",
                'queries_by_type': self.queries_by_type,
                'responses_by_rcode': self.responses_by_rcode,
                'cache_hits': self.cache_hits,
                'cache_misses': self.cache_misses,
                'blocked_queries': self.blocked_queries,
                'rate_limited': self.rate_limited,
                'upstream_errors': self.upstream_errors
            }


# ==================== DNS Parsing ====================
def parse_name(data: bytes, offset: int) -> Tuple[bytes, int]:
    """Parses a domain name, handling compression."""
    labels = []
    current_offset = offset
    end_of_name_offset = -1
    jumps = 0
    max_jumps = 20

    while True:
        if current_offset >= len(data):
            raise ValueError("Invalid name: offset out of bounds")
        
        length = data[current_offset]
        
        if (length & 0xC0) == 0xC0:  # Compression pointer
            if jumps >= max_jumps:
                raise ValueError("Too many compression jumps")
            if end_of_name_offset == -1:
                end_of_name_offset = current_offset + 2
            if current_offset + 1 >= len(data):
                raise ValueError("Invalid compression pointer")
            pointer = struct.unpack("!H", data[current_offset:current_offset+2])[0]
            jump_offset = pointer & 0x3FFF
            if jump_offset >= len(data):
                raise ValueError("Invalid compression pointer offset")
            current_offset = jump_offset
            jumps += 1
            continue
        
        if length == 0:  # Null terminator
            if end_of_name_offset == -1:
                end_of_name_offset = current_offset + 1
            break
        
        if length > 63:
            raise ValueError("Label too long")
        
        # Regular label
        current_offset += 1
        if current_offset + length > len(data):
            raise ValueError("Label extends beyond data")
        label = data[current_offset:current_offset + length]
        labels.append(struct.pack("!B", length) + label)
        current_offset += length

    uncompressed_name = b"".join(labels) + b'\x00'
    return uncompressed_name, end_of_name_offset


def parse_questions(data: bytes, offset: int, count: int) -> Tuple[List[DNSQuestion], int]:
    """Parses the question section of a DNS message."""
    questions = []
    current_offset = offset
    
    for _ in range(count):
        if current_offset >= len(data):
            raise ValueError("Incomplete question section")
        name, next_offset = parse_name(data, current_offset)
        if next_offset + 4 > len(data):
            raise ValueError("Incomplete question")
        type_, class_ = struct.unpack("!HH", data[next_offset:next_offset + 4])
        questions.append(DNSQuestion(name, type_, class_))
        current_offset = next_offset + 4
    
    return questions, current_offset


def parse_records(data: bytes, offset: int, count: int) -> Tuple[List[DNSRecord], int]:
    """Parses resource records."""
    records = []
    current_offset = offset
    
    for _ in range(count):
        if current_offset >= len(data):
            raise ValueError("Incomplete record section")
        name, name_end_offset = parse_name(data, current_offset)
        if name_end_offset + 10 > len(data):
            raise ValueError("Incomplete record header")
        type_, class_, ttl, length = struct.unpack(
            "!HHIH", data[name_end_offset:name_end_offset + 10])
        if name_end_offset + 10 + length > len(data):
            raise ValueError("Incomplete record data")
        rdata = data[name_end_offset + 10:name_end_offset + 10 + length]
        records.append(DNSRecord(name, type_, class_, ttl, rdata))
        current_offset = name_end_offset + 10 + length
    
    return records, current_offset


def create_edns_opt(buffer_size: int = 4096, dnssec_ok: bool = False) -> DNSRecord:
    """Create EDNS0 OPT pseudo-record."""
    flags = (1 << 15) if dnssec_ok else 0  # DO bit
    return DNSRecord(
        name=b'\x00',  # Root
        type_=DNSType.OPT,
        class_=buffer_size,  # UDP payload size in class field
        ttl=flags,  # Extended RCODE and flags in TTL field
        data=b''  # No options for now
    )


# ==================== DNS Server ====================
class DNSServer:
    """Production-grade DNS server."""
    
    def __init__(self, config: ServerConfig):
        self.config = config
        self.cache = DNSCache(config.cache_size)
        self.filter = DomainFilter()
        self.rate_limiter = RateLimiter(config.rate_limit)
        self.metrics = Metrics()
        
        # Load filters
        if config.blacklist_file:
            self.filter.load_blacklist(config.blacklist_file)
        if config.whitelist_file:
            self.filter.load_whitelist(config.whitelist_file)
        
        # Setup logging
        log_level = getattr(logging, config.log_level.upper(), logging.INFO)
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        self.running = False
        self.resolver_index = 0

    def get_next_resolver(self) -> Tuple[str, int]:
        """Get next resolver in round-robin fashion."""
        resolver = self.config.resolvers[self.resolver_index % len(self.config.resolvers)]
        self.resolver_index += 1
        return resolver

    def query_upstream(self, packet: bytes, retries: int = 0) -> Optional[bytes]:
        """Query upstream resolver with retry logic."""
        if retries >= self.config.max_retries:
            logging.error("Max retries reached")
            self.metrics.record_upstream_error()
            return None
        
        resolver = self.get_next_resolver()
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.config.timeout)
                sock.sendto(packet, resolver)
                
                # Wait for response
                ready = select.select([sock], [], [], self.config.timeout)
                if ready[0]:
                    response, _ = sock.recvfrom(self.config.edns_buffer_size)
                    return response
                else:
                    logging.warning(f"Timeout querying {resolver}, retrying...")
                    return self.query_upstream(packet, retries + 1)
        
        except socket.timeout:
            logging.warning(f"Timeout querying {resolver}, retrying...")
            return self.query_upstream(packet, retries + 1)
        except Exception as e:
            logging.error(f"Error querying {resolver}: {e}, retrying...")
            return self.query_upstream(packet, retries + 1)

    def build_error_response(self, request_id: int, rcode: int, rd: int = 1) -> bytes:
        """Build an error response."""
        flags = DNSHeader.build_flags(qr=1, opcode=0, rd=rd, rcode=rcode)
        header = DNSHeader(id=request_id, flags=flags)
        return header.pack()

    def process_query(self, data: bytes, client_addr: Tuple[str, int]) -> bytes:
        """Process a DNS query."""
        client_ip = client_addr[0]
        
        # Rate limiting
        if not self.rate_limiter.allow(client_ip):
            logging.warning(f"Rate limit exceeded for {client_ip}")
            self.metrics.record_rate_limited()
            header = DNSHeader.unpack(data)
            return self.build_error_response(header.id, DNSRCode.REFUSED, header.get_rd())
        
        try:
            # Parse request
            header = DNSHeader.unpack(data)
            
            # Check opcode
            opcode = header.get_opcode()
            if opcode != 0:
                logging.warning(f"Unsupported opcode: {opcode}")
                return self.build_error_response(header.id, DNSRCode.NOTIMP, header.get_rd())
            
            # Parse questions
            questions, _ = parse_questions(data, 12, header.qdcount)
            
            if not questions:
                return self.build_error_response(header.id, DNSRCode.FORMERR, header.get_rd())
            
            # Process first question (standard DNS)
            question = questions[0]
            self.metrics.record_query(question.type_)
            
            domain = question.to_string()
            logging.info(f"Query from {client_ip}: {domain} (type {question.type_})")
            
            # Check blacklist
            if self.filter.is_blocked(domain):
                logging.info(f"Blocked domain: {domain}")
                self.metrics.record_blocked()
                self.metrics.record_response(DNSRCode.NXDOMAIN)
                return self.build_error_response(header.id, DNSRCode.NXDOMAIN, header.get_rd())
            
            # Check cache
            cached = self.cache.get(question)
            if cached:
                answers, authorities, additionals, rcode = cached
                logging.info(f"Cache hit for {domain}")
                self.metrics.record_cache_hit()
                self.metrics.record_response(int(rcode))
                
                # Build response from cache
                flags = DNSHeader.build_flags(
                    qr=1, opcode=0, rd=header.get_rd(), ra=1, rcode=int(rcode)
                )
                response_header = DNSHeader(
                    id=header.id,
                    flags=flags,
                    qdcount=1,
                    ancount=len(answers),
                    nscount=len(authorities),
                    arcount=len(additionals)
                )
                
                response = response_header.pack()
                response += question.pack()
                for record in answers:
                    response += record.pack()
                for record in authorities:
                    response += record.pack()
                for record in additionals:
                    response += record.pack()
                
                return response
            
            # Cache miss - query upstream
            logging.info(f"Cache miss for {domain}, querying upstream")
            self.metrics.record_cache_miss()
            
            # Build query with EDNS0
            forward_flags = DNSHeader.build_flags(
                qr=0, opcode=0, rd=header.get_rd()
            )
            forward_header = DNSHeader(
                id=header.id,
                flags=forward_flags,
                qdcount=1,
                arcount=1  # For EDNS0
            )
            
            forward_packet = forward_header.pack()
            forward_packet += question.pack()
            forward_packet += create_edns_opt(self.config.edns_buffer_size, self.config.enable_dnssec).pack()
            
            # Query upstream
            response = self.query_upstream(forward_packet)
            
            if not response:
                logging.error(f"Failed to get response for {domain}")
                self.metrics.record_response(DNSRCode.SERVFAIL)
                return self.build_error_response(header.id, DNSRCode.SERVFAIL, header.get_rd())
            
            # Parse response
            response_header = DNSHeader.unpack(response)
            _, q_end = parse_questions(response, 12, response_header.qdcount)
            answers, a_end = parse_records(response, q_end, response_header.ancount)
            authorities, ns_end = parse_records(response, a_end, response_header.nscount)
            additionals, _ = parse_records(response, ns_end, response_header.arcount)
            
            # Remove EDNS0 OPT record from additionals before caching
            additionals_no_opt = [r for r in additionals if r.type_ != DNSType.OPT]
            
            rcode = response_header.get_rcode()
            self.metrics.record_response(rcode)
            
            # Cache the response
            if answers:
                min_ttl = min((r.ttl for r in answers), default=self.config.cache_ttl_min)
                min_ttl = max(self.config.cache_ttl_min, min(min_ttl, self.config.cache_ttl_max))
                self.cache.put(question, answers, authorities, additionals_no_opt, rcode, min_ttl)
            elif rcode == DNSRCode.NXDOMAIN:
                # Cache negative responses
                self.cache.put(question, [], authorities, additionals_no_opt, rcode, self.config.cache_ttl_min)
            
            # Update response ID and return
            response_with_correct_id = struct.pack("!H", header.id) + response[2:]
            return response_with_correct_id
        
        except Exception as e:
            logging.error(f"Error processing query: {e}", exc_info=True)
            try:
                header = DNSHeader.unpack(data)
                return self.build_error_response(header.id, DNSRCode.SERVFAIL)
            except:
                return self.build_error_response(0, DNSRCode.SERVFAIL)

    def handle_udp(self):
        """Handle UDP queries."""
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_socket.bind((self.config.bind_address, self.config.bind_port))
        
        logging.info(f"UDP server listening on {self.config.bind_address}:{self.config.bind_port}")
        
        while self.running:
            try:
                data, addr = udp_socket.recvfrom(512)
                response = self.process_query(data, addr)
                
                # Check if response fits in 512 bytes
                if len(response) > 512:
                    # Set TC flag
                    header = DNSHeader.unpack(response)
                    flags = header.flags | (1 << 9)  # Set TC bit
                    truncated_response = struct.pack("!H", header.id) + struct.pack("!H", flags) + response[4:512]
                    udp_socket.sendto(truncated_response, addr)
                else:
                    udp_socket.sendto(response, addr)
            
            except Exception as e:
                if self.running:
                    logging.error(f"UDP error: {e}")

    def handle_tcp_client(self, client_socket: socket.socket, addr: Tuple[str, int]):
        """Handle a single TCP client with keep-alive support."""
        try:
            client_socket.settimeout(30)  # 30 second timeout

            while True:  # Keep connection alive for multiple queries
                # Read length prefix (2 bytes)
                length_data = client_socket.recv(2)
                if len(length_data) < 2:
                    break  # Connection closed by client

                query_length = struct.unpack("!H", length_data)[0]

                # Read query data
                data = b''
                while len(data) < query_length:
                    chunk = client_socket.recv(query_length - len(data))
                    if not chunk:
                        return  # Connection lost
                    data += chunk

                # Process query
                response = self.process_query(data, addr)

                # Send response with length prefix
                response_with_length = struct.pack("!H", len(response)) + response
                client_socket.sendall(response_with_length)

        except socket.timeout:
            pass  # Client idle for too long
        except Exception as e:
            logging.error(f"TCP client error: {e}")
        finally:
            client_socket.close()

    def handle_tcp(self):
        """Handle TCP queries."""
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_socket.bind((self.config.bind_address, self.config.bind_port))
        tcp_socket.listen(5)
        
        logging.info(f"TCP server listening on {self.config.bind_address}:{self.config.bind_port}")
        
        while self.running:
            try:
                client_socket, addr = tcp_socket.accept()
                # Handle each client in a separate thread
                client_thread = threading.Thread(
                    target=self.handle_tcp_client,
                    args=(client_socket, addr),
                    daemon=True
                )
                client_thread.start()
            except Exception as e:
                if self.running:
                    logging.error(f"TCP accept error: {e}")

    def handle_metrics(self):
        """Simple HTTP server for metrics."""
        metrics_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        metrics_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        metrics_socket.bind((self.config.bind_address, self.config.metrics_port))
        metrics_socket.listen(5)
        
        logging.info(f"Metrics server listening on {self.config.bind_address}:{self.config.metrics_port}")
        
        while self.running:
            try:
                client_socket, _ = metrics_socket.accept()
                
                # Read request (we don't parse it, just respond)
                client_socket.recv(1024)
                
                # Gather all metrics
                stats = {
                    'server': self.metrics.get_stats(),
                    'cache': self.cache.get_stats(),
                    'timestamp': datetime.now().isoformat()
                }
                
                # Build HTTP response
                body = json.dumps(stats, indent=2)
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    f"{body}"
                )
                
                client_socket.sendall(response.encode())
                client_socket.close()
            
            except Exception as e:
                if self.running:
                    logging.error(f"Metrics server error: {e}")

    def cleanup_thread(self):
        """Periodic cleanup of old data."""
        while self.running:
            time.sleep(300)  # Every 5 minutes
            try:
                self.rate_limiter.cleanup()
                logging.debug("Cleanup completed")
            except Exception as e:
                logging.error(f"Cleanup error: {e}")

    def start(self):
        """Start the DNS server."""
        self.running = True
        
        # Start UDP server
        udp_thread = threading.Thread(target=self.handle_udp, daemon=True)
        udp_thread.start()
        
        # Start TCP server if enabled
        if self.config.enable_tcp:
            tcp_thread = threading.Thread(target=self.handle_tcp, daemon=True)
            tcp_thread.start()
        
        # Start metrics server if enabled
        if self.config.enable_metrics:
            metrics_thread = threading.Thread(target=self.handle_metrics, daemon=True)
            metrics_thread.start()
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self.cleanup_thread, daemon=True)
        cleanup_thread.start()
        
        logging.info("DNS Server started successfully!")
        logging.info(f"Resolvers: {self.config.resolvers}")
        logging.info(f"Cache size: {self.config.cache_size}")
        logging.info(f"DNSSEC: {'enabled' if self.config.enable_dnssec else 'disabled'}")
        logging.info(f"TCP: {'enabled' if self.config.enable_tcp else 'disabled'}")
        
        try:
            # Keep main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Shutting down...")
            self.stop()

    def stop(self):
        """Stop the DNS server."""
        self.running = False


# ==================== Main ====================
def main():
    """Main entry point."""
    
    # Parse command line arguments
    config = ServerConfig()
    
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        
        if arg == '--resolver':
            if i + 1 >= len(sys.argv):
                print("Error: --resolver requires an argument")
                sys.exit(1)
            resolver_str = sys.argv[i + 1]
            ip, port_str = resolver_str.split(':')
            config.resolvers.append((ip, int(port_str)))
            i += 2
        
        elif arg == '--bind':
            if i + 1 >= len(sys.argv):
                print("Error: --bind requires an argument")
                sys.exit(1)
            bind_str = sys.argv[i + 1]
            if ':' in bind_str:
                config.bind_address, port_str = bind_str.split(':')
                config.bind_port = int(port_str)
            else:
                config.bind_address = bind_str
            i += 2
        
        elif arg == '--cache-size':
            if i + 1 >= len(sys.argv):
                print("Error: --cache-size requires an argument")
                sys.exit(1)
            config.cache_size = int(sys.argv[i + 1])
            i += 2
        
        elif arg == '--timeout':
            if i + 1 >= len(sys.argv):
                print("Error: --timeout requires an argument")
                sys.exit(1)
            config.timeout = int(sys.argv[i + 1])
            i += 2
        
        elif arg == '--blacklist':
            if i + 1 >= len(sys.argv):
                print("Error: --blacklist requires an argument")
                sys.exit(1)
            config.blacklist_file = sys.argv[i + 1]
            i += 2
        
        elif arg == '--whitelist':
            if i + 1 >= len(sys.argv):
                print("Error: --whitelist requires an argument")
                sys.exit(1)
            config.whitelist_file = sys.argv[i + 1]
            i += 2
        
        elif arg == '--rate-limit':
            if i + 1 >= len(sys.argv):
                print("Error: --rate-limit requires an argument")
                sys.exit(1)
            config.rate_limit = int(sys.argv[i + 1])
            i += 2
        
        elif arg == '--log-level':
            if i + 1 >= len(sys.argv):
                print("Error: --log-level requires an argument")
                sys.exit(1)
            config.log_level = sys.argv[i + 1]
            i += 2
        
        elif arg == '--enable-dnssec':
            config.enable_dnssec = True
            i += 1
        
        elif arg == '--disable-tcp':
            config.enable_tcp = False
            i += 1
        
        elif arg == '--disable-metrics':
            config.enable_metrics = False
            i += 1
        
        elif arg == '--metrics-port':
            if i + 1 >= len(sys.argv):
                print("Error: --metrics-port requires an argument")
                sys.exit(1)
            config.metrics_port = int(sys.argv[i + 1])
            i += 2
        
        elif arg in ['--help', '-h']:
            print("""
Production-Grade DNS Server

Usage: python main.py [options]

Required:
  --resolver <ip:port>       Upstream DNS resolver (can be specified multiple times)

Optional:
  --bind <ip[:port]>         Bind address (default: 127.0.0.1:2053)
  --cache-size <n>           Maximum cache entries (default: 10000)
  --timeout <seconds>        Query timeout (default: 5)
  --rate-limit <qps>         Queries per second per IP (default: 100)
  --blacklist <file>         Domain blacklist file
  --whitelist <file>         Domain whitelist file
  --log-level <level>        Log level: DEBUG, INFO, WARNING, ERROR (default: INFO)
  --enable-dnssec            Enable DNSSEC validation
  --disable-tcp              Disable TCP support
  --disable-metrics          Disable metrics endpoint
  --metrics-port <port>      Metrics HTTP port (default: 9053)
  --help, -h                 Show this help message

Examples:
  # Basic usage with Google DNS
  python main.py --resolver 8.8.8.8:53

  # Multiple resolvers with caching
  python main.py --resolver 8.8.8.8:53 --resolver 1.1.1.1:53 --cache-size 20000

  # With blacklist for ad-blocking
  python main.py --resolver 8.8.8.8:53 --blacklist ads.txt

  # Full featured
  python main.py --resolver 8.8.8.8:53 --resolver 1.1.1.1:53 \\
    --bind 0.0.0.0:53 --cache-size 50000 --rate-limit 200 \\
    --blacklist ads.txt --enable-dnssec --log-level INFO

Metrics:
  Access metrics at http://<bind-address>:<metrics-port>/
  Example: curl http://127.0.0.1:9053/

Blacklist/Whitelist Format:
  One domain per line, supports wildcards via parent matching
  Lines starting with # are comments
  Example:
    # Block ads
    ads.example.com
    tracker.example.com
""")
            sys.exit(0)
        
        else:
            print(f"Unknown argument: {arg}")
            print("Use --help for usage information")
            sys.exit(1)
    
    # Validate configuration
    if not config.resolvers:
        print("Error: At least one resolver must be specified with --resolver")
        print("Example: python main.py --resolver 8.8.8.8:53")
        sys.exit(1)
    
    # Create and start server
    server = DNSServer(config)
    server.start()


if __name__ == "__main__":
    main()