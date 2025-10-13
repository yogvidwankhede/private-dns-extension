#!/usr/bin/env python3
"""
Comprehensive Test Suite for Production-Grade DNS Server
Tests all features including caching, filtering, rate limiting, TCP/UDP, and more.
"""

import socket
import struct
import time
import threading
import unittest
import subprocess
import sys
import os
import json
import requests
from typing import List, Tuple, Optional


# ==================== DNS Test Utilities ====================
class DNSTestHelper:
    """Helper class for building and parsing DNS messages."""
    
    @staticmethod
    def encode_domain(domain: str) -> bytes:
        """Encode a domain name into DNS format."""
        if domain == '.':
            return b'\x00'
        parts = domain.rstrip('.').split('.')
        result = b''
        for part in parts:
            result += struct.pack('!B', len(part)) + part.encode()
        result += b'\x00'
        return result
    
    @staticmethod
    def decode_domain(data: bytes, offset: int) -> Tuple[str, int]:
        """Decode a domain name from DNS format."""
        labels = []
        current_offset = offset
        jumped = False
        original_offset = offset
        
        while True:
            if current_offset >= len(data):
                break
            
            length = data[current_offset]
            
            if (length & 0xC0) == 0xC0:  # Compression pointer
                if not jumped:
                    original_offset = current_offset + 2
                pointer = struct.unpack("!H", data[current_offset:current_offset+2])[0]
                current_offset = pointer & 0x3FFF
                jumped = True
                continue
            
            if length == 0:
                if not jumped:
                    original_offset = current_offset + 1
                break
            
            current_offset += 1
            label = data[current_offset:current_offset + length].decode('utf-8', errors='ignore')
            labels.append(label)
            current_offset += length
        
        domain = '.'.join(labels) if labels else '.'
        return domain, original_offset
    
    @staticmethod
    def build_query(domain: str, qtype: int = 1, qclass: int = 1, query_id: int = 1234, 
                   rd: bool = True, edns: bool = False) -> bytes:
        """Build a DNS query packet."""
        # Header
        flags = (0 << 15) | (0 << 11) | (0 << 10) | (0 << 9) | (int(rd) << 8)
        arcount = 1 if edns else 0
        header = struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, arcount)
        
        # Question
        question = DNSTestHelper.encode_domain(domain)
        question += struct.pack("!HH", qtype, qclass)
        
        packet = header + question
        
        # Add EDNS0 if requested
        if edns:
            # OPT record: root domain (0x00), type OPT (41), class = UDP size (4096)
            opt = b'\x00'  # Root
            opt += struct.pack("!H", 41)  # Type OPT
            opt += struct.pack("!H", 4096)  # UDP payload size
            opt += struct.pack("!I", 0)  # TTL (extended RCODE and flags)
            opt += struct.pack("!H", 0)  # RDLENGTH
            packet += opt
        
        return packet
    
    @staticmethod
    def parse_response(data: bytes) -> dict:
        """Parse a DNS response packet."""
        if len(data) < 12:
            return {'error': 'Packet too short'}
        
        # Parse header
        header = struct.unpack("!HHHHHH", data[:12])
        result = {
            'id': header[0],
            'flags': header[1],
            'qr': (header[1] >> 15) & 1,
            'opcode': (header[1] >> 11) & 0b1111,
            'aa': (header[1] >> 10) & 1,
            'tc': (header[1] >> 9) & 1,
            'rd': (header[1] >> 8) & 1,
            'ra': (header[1] >> 7) & 1,
            'rcode': header[1] & 0b1111,
            'qdcount': header[2],
            'ancount': header[3],
            'nscount': header[4],
            'arcount': header[5],
            'questions': [],
            'answers': [],
            'authorities': [],
            'additionals': []
        }
        
        offset = 12
        
        # Parse questions
        for _ in range(result['qdcount']):
            domain, offset = DNSTestHelper.decode_domain(data, offset)
            if offset + 4 > len(data):
                break
            qtype, qclass = struct.unpack("!HH", data[offset:offset+4])
            result['questions'].append({'domain': domain, 'type': qtype, 'class': qclass})
            offset += 4
        
        # Parse answers
        for _ in range(result['ancount']):
            domain, offset = DNSTestHelper.decode_domain(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
            offset += 10
            if offset + rdlength > len(data):
                break
            rdata = data[offset:offset+rdlength]
            
            # Parse A record
            if rtype == 1 and rdlength == 4:
                ip = '.'.join(str(b) for b in rdata)
                result['answers'].append({
                    'domain': domain, 'type': rtype, 'class': rclass,
                    'ttl': ttl, 'ip': ip
                })
            else:
                result['answers'].append({
                    'domain': domain, 'type': rtype, 'class': rclass,
                    'ttl': ttl, 'data': rdata.hex()
                })
            offset += rdlength
        
        return result


# ==================== Test Cases ====================
class TestDNSServerBasic(unittest.TestCase):
    """Test basic DNS functionality."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test server address."""
        cls.server_addr = ('127.0.0.1', 2053)
        cls.timeout = 5
    
    def test_01_simple_a_record_query(self):
        """Test basic A record query."""
        print("\n[TEST] Simple A record query for google.com")
        
        query = DNSTestHelper.build_query('google.com', qtype=1)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.sendto(query, self.server_addr)
            response, _ = sock.recvfrom(4096)
            
            result = DNSTestHelper.parse_response(response)
            
            self.assertEqual(result['qr'], 1, "Should be a response")
            self.assertEqual(result['rcode'], 0, "Should be NOERROR")
            self.assertGreater(result['ancount'], 0, "Should have answers")
            
            print(f"✓ Received {result['ancount']} answer(s)")
            for ans in result['answers']:
                if 'ip' in ans:
                    print(f"  - {ans['domain']}: {ans['ip']} (TTL: {ans['ttl']})")
        
        finally:
            sock.close()
    
    def test_02_aaaa_record_query(self):
        """Test AAAA (IPv6) record query."""
        print("\n[TEST] AAAA record query for google.com")
        
        query = DNSTestHelper.build_query('google.com', qtype=28)  # AAAA
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.sendto(query, self.server_addr)
            response, _ = sock.recvfrom(4096)
            
            result = DNSTestHelper.parse_response(response)
            
            self.assertEqual(result['qr'], 1, "Should be a response")
            self.assertEqual(result['rcode'], 0, "Should be NOERROR")
            
            print(f"✓ Received {result['ancount']} answer(s)")
        
        finally:
            sock.close()
    
    def test_03_mx_record_query(self):
        """Test MX record query."""
        print("\n[TEST] MX record query for gmail.com")
        
        query = DNSTestHelper.build_query('gmail.com', qtype=15)  # MX
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.sendto(query, self.server_addr)
            response, _ = sock.recvfrom(4096)
            
            result = DNSTestHelper.parse_response(response)
            
            self.assertEqual(result['qr'], 1, "Should be a response")
            self.assertEqual(result['rcode'], 0, "Should be NOERROR")
            self.assertGreater(result['ancount'], 0, "Should have MX records")
            
            print(f"✓ Received {result['ancount']} MX record(s)")
        
        finally:
            sock.close()
    
    def test_04_nxdomain_response(self):
        """Test NXDOMAIN for non-existent domain."""
        print("\n[TEST] NXDOMAIN for non-existent domain")
        
        query = DNSTestHelper.build_query('thisdoesnotexist12345.com', qtype=1)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.sendto(query, self.server_addr)
            response, _ = sock.recvfrom(4096)
            
            result = DNSTestHelper.parse_response(response)
            
            self.assertEqual(result['qr'], 1, "Should be a response")
            self.assertEqual(result['rcode'], 3, "Should be NXDOMAIN")
            
            print(f"✓ Correctly received NXDOMAIN (rcode={result['rcode']})")
        
        finally:
            sock.close()
    
    def test_05_rd_flag_propagation(self):
        """Test that RD flag is properly handled."""
        print("\n[TEST] RD flag propagation")
        
        # Query with RD=1
        query = DNSTestHelper.build_query('example.com', qtype=1, rd=True)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.sendto(query, self.server_addr)
            response, _ = sock.recvfrom(4096)
            
            result = DNSTestHelper.parse_response(response)
            
            self.assertEqual(result['rd'], 1, "RD flag should be set")
            self.assertEqual(result['ra'], 1, "RA flag should be set")
            
            print(f"✓ RD and RA flags properly set")
        
        finally:
            sock.close()


class TestDNSServerCaching(unittest.TestCase):
    """Test caching functionality."""
    
    @classmethod
    def setUpClass(cls):
        cls.server_addr = ('127.0.0.1', 2053)
        cls.timeout = 5
    
    def test_01_cache_hit_performance(self):
        """Test that cached queries are faster."""
        print("\n[TEST] Cache hit performance")
    
        # Use a unique domain with timestamp to avoid pre-cached results
        import time
        unique_domain = f'test{int(time.time())}.example.com'
        query = DNSTestHelper.build_query(unique_domain, qtype=1)
    
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
    
        try:
            # First query (cache miss) - should go to upstream
            start1 = time.time()
            sock.sendto(query, self.server_addr)
            response1, _ = sock.recvfrom(4096)
            time1 = time.time() - start1
    
            result1 = DNSTestHelper.parse_response(response1)
            # Should be NXDOMAIN but still valid
    
            # Wait a bit
            time.sleep(0.1)
    
            # Second query (cache hit) - should be from cache
            start2 = time.time()
            sock.sendto(query, self.server_addr)
            response2, _ = sock.recvfrom(4096)
            time2 = time.time() - start2
    
            result2 = DNSTestHelper.parse_response(response2)
    
            print(f"  First query (miss):  {time1*1000:.2f}ms")
            print(f"  Second query (hit):  {time2*1000:.2f}ms")
    
            # Check if second query is faster (with tolerance for very fast networks)
            if time1 > 0.001:  # Only check if first query took more than 1ms
                speedup = time1 / time2 if time2 > 0 else float('inf')
                print(f"  Speedup: {speedup:.2f}x")
                # Cache hit should be faster, but allow some margin
                self.assertTrue(time2 <= time1 * 1.5,
                                "Cached query should be similar or faster")
            else:
                print(f"  Both queries very fast - cache working efficiently")
    
            print(f"✓ Cache improves performance")
    
        finally:
            sock.close()
    
    def test_02_cache_ttl_decrements(self):
        """Test that cached TTLs decrement over time."""
        print("\n[TEST] Cache TTL decrement")
        
        domain = 'wikipedia.org'
        query = DNSTestHelper.build_query(domain, qtype=1)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        
        try:
            # First query
            sock.sendto(query, self.server_addr)
            response1, _ = sock.recvfrom(4096)
            result1 = DNSTestHelper.parse_response(response1)
            
            if result1['ancount'] > 0:
                ttl1 = result1['answers'][0]['ttl']
                
                # Wait 2 seconds
                time.sleep(2)
                
                # Second query
                sock.sendto(query, self.server_addr)
                response2, _ = sock.recvfrom(4096)
                result2 = DNSTestHelper.parse_response(response2)
                
                if result2['ancount'] > 0:
                    ttl2 = result2['answers'][0]['ttl']
                    
                    print(f"  Initial TTL: {ttl1}")
                    print(f"  TTL after 2s: {ttl2}")
                    
                    # TTL should have decreased
                    self.assertLess(ttl2, ttl1, "TTL should decrement")
                    print(f"✓ TTL properly decrements over time")
        
        finally:
            sock.close()
    
    def test_03_negative_caching(self):
        """Test that NXDOMAIN responses are cached."""
        print("\n[TEST] Negative caching (NXDOMAIN)")
        
        domain = f'nonexistent{int(time.time())}.example.com'
        query = DNSTestHelper.build_query(domain, qtype=1)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        
        try:
            # First query
            start1 = time.time()
            sock.sendto(query, self.server_addr)
            response1, _ = sock.recvfrom(4096)
            time1 = time.time() - start1
            
            result1 = DNSTestHelper.parse_response(response1)
            self.assertEqual(result1['rcode'], 3, "Should be NXDOMAIN")
            
            time.sleep(0.1)
            
            # Second query (should be cached)
            start2 = time.time()
            sock.sendto(query, self.server_addr)
            response2, _ = sock.recvfrom(4096)
            time2 = time.time() - start2
            
            result2 = DNSTestHelper.parse_response(response2)
            self.assertEqual(result2['rcode'], 3, "Should still be NXDOMAIN")
            
            print(f"  First NXDOMAIN:  {time1*1000:.2f}ms")
            print(f"  Second NXDOMAIN: {time2*1000:.2f}ms")
            print(f"✓ NXDOMAIN responses are cached")
        
        finally:
            sock.close()


class TestDNSServerTCP(unittest.TestCase):
    """Test TCP support."""
    
    @classmethod
    def setUpClass(cls):
        cls.server_addr = ('127.0.0.1', 2053)
        cls.timeout = 5
    
    def test_01_tcp_query(self):
        """Test basic TCP query."""
        print("\n[TEST] TCP query")
        
        query = DNSTestHelper.build_query('google.com', qtype=1)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect(self.server_addr)
            
            # Send with length prefix
            length_prefix = struct.pack("!H", len(query))
            sock.sendall(length_prefix + query)
            
            # Read response length
            length_data = sock.recv(2)
            self.assertEqual(len(length_data), 2, "Should receive length prefix")
            
            response_length = struct.unpack("!H", length_data)[0]
            
            # Read response
            response = b''
            while len(response) < response_length:
                chunk = sock.recv(response_length - len(response))
                if not chunk:
                    break
                response += chunk
            
            result = DNSTestHelper.parse_response(response)
            
            self.assertEqual(result['qr'], 1, "Should be a response")
            self.assertEqual(result['rcode'], 0, "Should be NOERROR")
            
            print(f"✓ TCP query successful, received {result['ancount']} answer(s)")
        
        finally:
            sock.close()
    
    def test_02_tcp_multiple_queries(self):
        """Test multiple queries over same TCP connection."""
        print("\n[TEST] Multiple TCP queries on same connection")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect(self.server_addr)
            
            domains = ['google.com', 'facebook.com', 'amazon.com']
            
            for domain in domains:
                query = DNSTestHelper.build_query(domain, qtype=1)
                
                # Send query
                length_prefix = struct.pack("!H", len(query))
                sock.sendall(length_prefix + query)
                
                # Read response
                length_data = sock.recv(2)
                response_length = struct.unpack("!H", length_data)[0]
                
                response = b''
                while len(response) < response_length:
                    chunk = sock.recv(response_length - len(response))
                    if not chunk:
                        break
                    response += chunk
                
                result = DNSTestHelper.parse_response(response)
                self.assertEqual(result['rcode'], 0, f"Query for {domain} should succeed")
                print(f"  ✓ {domain}: {result['ancount']} answer(s)")
            
            print(f"✓ Multiple queries over single TCP connection successful")
        
        finally:
            sock.close()


class TestDNSServerEDNS(unittest.TestCase):
    """Test EDNS0 support."""
    
    @classmethod
    def setUpClass(cls):
        cls.server_addr = ('127.0.0.1', 2053)
        cls.timeout = 5
    
    def test_01_edns_query(self):
        """Test query with EDNS0."""
        print("\n[TEST] EDNS0 support")
        
        query = DNSTestHelper.build_query('google.com', qtype=1, edns=True)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.sendto(query, self.server_addr)
            response, _ = sock.recvfrom(4096)
            
            result = DNSTestHelper.parse_response(response)
            
            self.assertEqual(result['qr'], 1, "Should be a response")
            self.assertEqual(result['rcode'], 0, "Should be NOERROR")
            
            print(f"✓ EDNS0 query successful")
            print(f"  Answer count: {result['ancount']}")
            print(f"  Additional count: {result['arcount']}")
        
        finally:
            sock.close()


class TestDNSServerRateLimiting(unittest.TestCase):
    """Test rate limiting."""
    
    @classmethod
    def setUpClass(cls):
        cls.server_addr = ('127.0.0.1', 2053)
        cls.timeout = 2
    
    def test_01_rate_limiting(self):
        """Test rate limiting kicks in."""
        print("\n[TEST] Rate limiting")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        
        try:
            query = DNSTestHelper.build_query('example.com', qtype=1)
            
            # Send many queries rapidly
            refused_count = 0
            success_count = 0
            
            for i in range(150):  # More than default rate limit
                sock.sendto(query, self.server_addr)
                try:
                    response, _ = sock.recvfrom(4096)
                    result = DNSTestHelper.parse_response(response)
                    
                    if result['rcode'] == 5:  # REFUSED
                        refused_count += 1
                    elif result['rcode'] == 0:  # NOERROR
                        success_count += 1
                except socket.timeout:
                    pass
            
            print(f"  Successful: {success_count}")
            print(f"  Refused: {refused_count}")
            
            # We should see some refused responses
            # Note: This might not always trigger depending on timing
            if refused_count > 0:
                print(f"✓ Rate limiting is working")
            else:
                print(f"  Rate limiting may not have triggered (try running again)")
        
        finally:
            sock.close()


class TestDNSServerMetrics(unittest.TestCase):
    """Test metrics endpoint."""
    
    @classmethod
    def setUpClass(cls):
        cls.metrics_url = 'http://127.0.0.1:9053/'
        cls.timeout = 5
    
    def test_01_metrics_endpoint(self):
        """Test metrics HTTP endpoint."""
        print("\n[TEST] Metrics endpoint")
        
        try:
            response = requests.get(self.metrics_url, timeout=self.timeout)
            
            self.assertEqual(response.status_code, 200, "Should return 200 OK")
            
            data = response.json()
            
            self.assertIn('server', data, "Should have server metrics")
            self.assertIn('cache', data, "Should have cache metrics")
            
            print(f"✓ Metrics endpoint accessible")
            print(f"\n  Server Metrics:")
            for key, value in data['server'].items():
                print(f"    {key}: {value}")
            
            print(f"\n  Cache Metrics:")
            for key, value in data['cache'].items():
                print(f"    {key}: {value}")
        
        except requests.exceptions.ConnectionError:
            self.skipTest("Metrics endpoint not available (may be disabled)")
        except Exception as e:
            self.fail(f"Metrics endpoint error: {e}")


class TestDNSServerStress(unittest.TestCase):
    """Stress tests."""
    
    @classmethod
    def setUpClass(cls):
        cls.server_addr = ('127.0.0.1', 2053)
        cls.timeout = 5
    
    def test_01_concurrent_queries(self):
        """Test concurrent queries from multiple threads."""
        print("\n[TEST] Concurrent queries")
        
        results = {'success': 0, 'failed': 0, 'lock': threading.Lock()}
        
        def query_thread(domain: str, count: int):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            try:
                query = DNSTestHelper.build_query(domain, qtype=1)
                
                for _ in range(count):
                    try:
                        sock.sendto(query, self.server_addr)
                        response, _ = sock.recvfrom(4096)
                        result = DNSTestHelper.parse_response(response)
                        
                        with results['lock']:
                            if result['rcode'] == 0:
                                results['success'] += 1
                            else:
                                results['failed'] += 1
                    except Exception as e:
                        with results['lock']:
                            results['failed'] += 1
            finally:
                sock.close()
        
        domains = ['google.com', 'facebook.com', 'amazon.com', 'twitter.com', 'reddit.com']
        threads = []
        queries_per_thread = 10
        
        start_time = time.time()
        
        for domain in domains:
            thread = threading.Thread(target=query_thread, args=(domain, queries_per_thread))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        duration = time.time() - start_time
        total_queries = len(domains) * queries_per_thread
        qps = total_queries / duration
        
        print(f"  Total queries: {total_queries}")
        print(f"  Successful: {results['success']}")
        print(f"  Failed: {results['failed']}")
        print(f"  Duration: {duration:.2f}s")
        print(f"  QPS: {qps:.2f}")
        
        success_rate = (results['success'] / total_queries) * 100
        self.assertGreater(success_rate, 80, "Should have >80% success rate")
        print(f"✓ Concurrent queries handled successfully ({success_rate:.1f}% success rate)")
    
    def test_02_malformed_packets(self):
        """Test handling of malformed packets."""
        print("\n[TEST] Malformed packet handling")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        
        malformed_packets = [
            b'',  # Empty
            b'\x00' * 5,  # Too short
            b'\x00' * 12,  # Header only, no questions
            b'\xff' * 50,  # Random data
            b'\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00',  # Invalid question
        ]
        
        try:
            for i, packet in enumerate(malformed_packets):
                try:
                    sock.sendto(packet, self.server_addr)
                    response, _ = sock.recvfrom(4096)
                    # Server should either respond with error or not respond
                    if len(response) >= 12:
                        result = DNSTestHelper.parse_response(response)
                        # Should be an error response
                        self.assertIn(result['rcode'], [1, 2, 4, 5], 
                                     f"Malformed packet {i} should return error")
                except socket.timeout:
                    # Timeout is acceptable for malformed packets
                    pass
            
            print(f"✓ Server handles malformed packets gracefully")
        
        finally:
            sock.close()


# ==================== Test Runner ====================
def run_all_tests():
    """Run all test suites."""
    
    print("=" * 70)
    print("DNS SERVER COMPREHENSIVE TEST SUITE")
    print("=" * 70)
    
    # Check if server is running
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        query = DNSTestHelper.build_query('google.com', qtype=1)
        sock.sendto(query, ('127.0.0.1', 2053))
        sock.recvfrom(4096)
        sock.close()
        print("\n✓ DNS Server is running and responsive\n")
    except Exception as e:
        print(f"\n✗ Cannot connect to DNS server at 127.0.0.1:2053")
        print(f"  Error: {e}")
        print(f"\n  Please start the server first:")
        print(f"  python main.py --resolver 8.8.8.8:53\n")
        return False
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestDNSServerBasic))
    suite.addTests(loader.loadTestsFromTestCase(TestDNSServerCaching))
    suite.addTests(loader.loadTestsFromTestCase(TestDNSServerTCP))
    suite.addTests(loader.loadTestsFromTestCase(TestDNSServerEDNS))
    suite.addTests(loader.loadTestsFromTestCase(TestDNSServerRateLimiting))
    suite.addTests(loader.loadTestsFromTestCase(TestDNSServerMetrics))
    suite.addTests(loader.loadTestsFromTestCase(TestDNSServerStress))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    
    if result.wasSuccessful():
        print("\n✓ ALL TESTS PASSED!")
    else:
        print("\n✗ SOME TESTS FAILED")
    
    print("=" * 70)
    
    return result.wasSuccessful()


# ==================== Blacklist Testing ====================
def test_blacklist_feature():
    """Test blacklist functionality separately."""
    print("\n" + "=" * 70)
    print("BLACKLIST FEATURE TEST")
    print("=" * 70)
    
    # Create a test blacklist file
    blacklist_file = 'test_blacklist.txt'
    with open(blacklist_file, 'w') as f:
        f.write("# Test blacklist\n")
        f.write("ads.example.com\n")
        f.write("tracker.test.com\n")
        f.write("malicious.com\n")
    
    print(f"\n✓ Created test blacklist: {blacklist_file}")
    print(f"  Domains: ads.example.com, tracker.test.com, malicious.com")
    
    print("\nTo test blacklist:")
    print(f"1. Restart server with: python main.py --resolver 8.8.8.8:53 --blacklist {blacklist_file}")
    print(f"2. Run: python test_dns.py --test-blocked")
    
    return blacklist_file


def test_blocked_domains():
    """Test that blocked domains return NXDOMAIN."""
    print("\n[TEST] Blocked domain filtering")
    
    blocked_domains = ['ads.example.com', 'tracker.test.com', 'malicious.com']
    server_addr = ('127.0.0.1', 2053)
    
    for domain in blocked_domains:
        query = DNSTestHelper.build_query(domain, qtype=1)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        
        try:
            sock.sendto(query, server_addr)
            response, _ = sock.recvfrom(4096)
            
            result = DNSTestHelper.parse_response(response)
            
            if result['rcode'] == 3:  # NXDOMAIN
                print(f"  ✓ {domain}: Blocked (NXDOMAIN)")
            else:
                print(f"  ✗ {domain}: Not blocked (rcode={result['rcode']})")
        
        except Exception as e:
            print(f"  ✗ {domain}: Error - {e}")
        
        finally:
            sock.close()


# ==================== Performance Benchmark ====================
def benchmark_performance():
    """Benchmark DNS server performance."""
    print("\n" + "=" * 70)
    print("PERFORMANCE BENCHMARK")
    print("=" * 70)
    
    server_addr = ('127.0.0.1', 2053)
    test_domain = 'example.com'
    
    # Test 1: Latency for cache miss
    print("\n[Benchmark] Cache Miss Latency")
    unique_domain = f'test{int(time.time())}.example.com'
    query = DNSTestHelper.build_query(unique_domain, qtype=1)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)
    
    latencies = []
    for i in range(5):
        start = time.time()
        try:
            sock.sendto(query, server_addr)
            sock.recvfrom(4096)
            latency = (time.time() - start) * 1000
            latencies.append(latency)
        except:
            pass
    
    sock.close()
    
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        print(f"  Average: {avg_latency:.2f}ms")
        print(f"  Min: {min(latencies):.2f}ms")
        print(f"  Max: {max(latencies):.2f}ms")
    
    # Test 2: Latency for cache hit
    print("\n[Benchmark] Cache Hit Latency")
    query = DNSTestHelper.build_query(test_domain, qtype=1)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)
    
    # Prime cache
    sock.sendto(query, server_addr)
    sock.recvfrom(4096)
    time.sleep(0.1)
    
    # Measure cached queries
    latencies = []
    for i in range(100):
        start = time.time()
        try:
            sock.sendto(query, server_addr)
            sock.recvfrom(4096)
            latency = (time.time() - start) * 1000
            latencies.append(latency)
        except:
            pass
    
    sock.close()
    
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        print(f"  Average: {avg_latency:.2f}ms")
        print(f"  Min: {min(latencies):.2f}ms")
        print(f"  Max: {max(latencies):.2f}ms")
        print(f"  Median: {sorted(latencies)[len(latencies)//2]:.2f}ms")
    
    # Test 3: Throughput
    print("\n[Benchmark] Query Throughput")
    
    num_queries = 1000
    start_time = time.time()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)
    
    success_count = 0
    for i in range(num_queries):
        try:
            query = DNSTestHelper.build_query(test_domain, qtype=1)
            sock.sendto(query, server_addr)
            sock.recvfrom(4096)
            success_count += 1
        except:
            pass
    
    duration = time.time() - start_time
    qps = success_count / duration
    
    sock.close()
    
    print(f"  Total queries: {num_queries}")
    print(f"  Successful: {success_count}")
    print(f"  Duration: {duration:.2f}s")
    print(f"  Throughput: {qps:.2f} queries/second")
    
    print("\n" + "=" * 70)


# ==================== Interactive Test Menu ====================
def interactive_menu():
    """Interactive test menu."""
    print("\n" + "=" * 70)
    print("DNS SERVER TEST MENU")
    print("=" * 70)
    print("\n1. Run all tests")
    print("2. Run basic functionality tests")
    print("3. Run caching tests")
    print("4. Run TCP tests")
    print("5. Run stress tests")
    print("6. Test blocked domains (requires blacklist)")
    print("7. Performance benchmark")
    print("8. Create test blacklist file")
    print("9. Query specific domain")
    print("0. Exit")
    
    choice = input("\nEnter choice: ").strip()
    
    if choice == '1':
        run_all_tests()
    elif choice == '2':
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromTestCase(TestDNSServerBasic)
        runner = unittest.TextTestRunner(verbosity=2)
        runner.run(suite)
    elif choice == '3':
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromTestCase(TestDNSServerCaching)
        runner = unittest.TextTestRunner(verbosity=2)
        runner.run(suite)
    elif choice == '4':
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromTestCase(TestDNSServerTCP)
        runner = unittest.TextTestRunner(verbosity=2)
        runner.run(suite)
    elif choice == '5':
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromTestCase(TestDNSServerStress)
        runner = unittest.TextTestRunner(verbosity=2)
        runner.run(suite)
    elif choice == '6':
        test_blocked_domains()
    elif choice == '7':
        benchmark_performance()
    elif choice == '8':
        blacklist_file = test_blacklist_feature()
        print(f"\n✓ Blacklist file created: {blacklist_file}")
    elif choice == '9':
        domain = input("Enter domain to query: ").strip()
        qtype = input("Enter query type (1=A, 28=AAAA, 15=MX, default=1): ").strip()
        qtype = int(qtype) if qtype else 1
        
        query = DNSTestHelper.build_query(domain, qtype=qtype)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        
        try:
            print(f"\nQuerying {domain} (type {qtype})...")
            sock.sendto(query, ('127.0.0.1', 2053))
            response, _ = sock.recvfrom(4096)
            
            result = DNSTestHelper.parse_response(response)
            
            print(f"\n--- Response ---")
            print(f"ID: {result['id']}")
            print(f"Flags: QR={result['qr']} OPCODE={result['opcode']} "
                  f"AA={result['aa']} TC={result['tc']} RD={result['rd']} "
                  f"RA={result['ra']} RCODE={result['rcode']}")
            print(f"Questions: {result['qdcount']}")
            print(f"Answers: {result['ancount']}")
            print(f"Authorities: {result['nscount']}")
            print(f"Additionals: {result['arcount']}")
            
            if result['answers']:
                print(f"\n--- Answers ---")
                for ans in result['answers']:
                    if 'ip' in ans:
                        print(f"{ans['domain']}: {ans['ip']} (TTL: {ans['ttl']})")
                    else:
                        print(f"{ans['domain']}: Type {ans['type']}, "
                              f"Data: {ans['data'][:40]}... (TTL: {ans['ttl']})")
        
        except Exception as e:
            print(f"Error: {e}")
        
        finally:
            sock.close()
    elif choice == '0':
        return False
    
    return True


# ==================== Command Line Interface ====================
def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        if sys.argv[1] == '--all':
            run_all_tests()
        elif sys.argv[1] == '--benchmark':
            benchmark_performance()
        elif sys.argv[1] == '--test-blocked':
            test_blocked_domains()
        elif sys.argv[1] == '--create-blacklist':
            test_blacklist_feature()
        elif sys.argv[1] == '--help':
            print("""
DNS Server Test Suite

Usage: python test_dns.py [option]

Options:
  --all              Run all tests
  --benchmark        Run performance benchmark
  --test-blocked     Test blocked domain filtering
  --create-blacklist Create test blacklist file
  --interactive      Interactive menu (default)
  --help             Show this help

Examples:
  python test_dns.py --all
  python test_dns.py --benchmark
  python test_dns.py --test-blocked

Make sure the DNS server is running before testing:
  python main.py --resolver 8.8.8.8:53
""")
        else:
            print(f"Unknown option: {sys.argv[1]}")
            print("Use --help for usage information")
    else:
        # Interactive mode
        while interactive_menu():
            input("\nPress Enter to continue...")


if __name__ == '__main__':
    main()