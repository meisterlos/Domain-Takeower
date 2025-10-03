#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced DNS Analyzer for Domain Takeover Detection
Enhanced DNS record analysis and CNAME chain detection
"""

import dns.resolver
import dns.query
import dns.zone
import socket
import threading
import concurrent.futures
from urllib.parse import urlparse
import re
import json
from datetime import datetime

class AdvancedDNSAnalyzer:
    def __init__(self):
        self.dns_cache = {}
        self.cname_chains = {}
        self.suspicious_records = []
        
    def analyze_domain_dns(self, domain):
        """Kapsamlı DNS analizi"""
        results = {
            'domain': domain,
            'a_records': [],
            'cname_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'srv_records': [],
            'cname_chains': [],
            'suspicious_records': [],
            'takeover_indicators': []
        }
        
        # DNS kayıtlarını analiz et
        self.get_dns_records(domain, results)
        
        # CNAME zincirlerini takip et
        self.analyze_cname_chains(domain, results)
        
        # Şüpheli kayıtları tespit et
        self.detect_suspicious_records(results)
        
        # Domain takeover göstergelerini kontrol et
        self.check_takeover_indicators(results)
        
        return results
        
    def get_dns_records(self, domain, results):
        """DNS kayıtlarını al"""
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                
                for answer in answers:
                    record_data = {
                        'type': record_type,
                        'value': str(answer),
                        'ttl': answer.ttl if hasattr(answer, 'ttl') else None
                    }
                    
                    if record_type == 'A':
                        results['a_records'].append(record_data)
                    elif record_type == 'AAAA':
                        results['a_records'].append(record_data)  # IPv6'ları da A kayıtlarına ekle
                    elif record_type == 'CNAME':
                        results['cname_records'].append(record_data)
                    elif record_type == 'MX':
                        results['mx_records'].append(record_data)
                    elif record_type == 'NS':
                        results['ns_records'].append(record_data)
                    elif record_type == 'TXT':
                        results['txt_records'].append(record_data)
                    elif record_type == 'SRV':
                        results['srv_records'].append(record_data)
                        
            except dns.resolver.NXDOMAIN:
                # Domain bulunamadı - potansiyel takeover
                results['takeover_indicators'].append({
                    'type': 'NXDOMAIN',
                    'domain': domain,
                    'severity': 'HIGH',
                    'description': 'Domain not found - potential takeover target'
                })
            except dns.resolver.NoAnswer:
                pass  # Bu kayıt türü için cevap yok
            except Exception as e:
                pass  # Diğer DNS hataları
                
    def analyze_cname_chains(self, domain, results):
        """CNAME zincirlerini analiz et"""
        visited = set()
        chain = []
        
        self.follow_cname_chain(domain, chain, visited, results)
        
    def follow_cname_chain(self, domain, chain, visited, results):
        """CNAME zincirini takip et"""
        if domain in visited:
            return  # Sonsuz döngü önleme
            
        visited.add(domain)
        chain.append(domain)
        
        try:
            # CNAME kaydını kontrol et
            answers = dns.resolver.resolve(domain, 'CNAME')
            for answer in answers:
                target = str(answer).rstrip('.')
                
                # Hedef domain'i analiz et
                self.analyze_cname_target(target, domain, results)
                
                # Zinciri devam ettir
                if target not in visited:
                    self.follow_cname_chain(target, chain.copy(), visited, results)
                    
        except dns.resolver.NoAnswer:
            # CNAME yok, zincir sona erdi
            if len(chain) > 1:
                results['cname_chains'].append({
                    'chain': chain,
                    'length': len(chain),
                    'final_target': chain[-1]
                })
        except Exception:
            pass
            
    def analyze_cname_target(self, target, source_domain, results):
        """CNAME hedefini analiz et"""
        # Bilinen takeover servisleri
        takeover_services = {
            'github.io': 'GitHub Pages',
            'gitlab.io': 'GitLab Pages',
            'netlify.app': 'Netlify',
            'vercel.app': 'Vercel',
            'herokuapp.com': 'Heroku',
            'azurewebsites.net': 'Azure App Service',
            'cloudapp.net': 'Azure Cloud Services',
            's3-website': 'AWS S3',
            's3.amazonaws.com': 'AWS S3',
            'firebaseapp.com': 'Firebase',
            'appspot.com': 'Google App Engine',
            'tumblr.com': 'Tumblr',
            'wordpress.com': 'WordPress.com',
            'blogspot.com': 'Blogger',
            'medium.com': 'Medium'
        }
        
        # Takeover servisi kontrolü
        for service_domain, service_name in takeover_services.items():
            if service_domain in target:
                results['takeover_indicators'].append({
                    'type': 'CNAME_TAKEOVER',
                    'domain': source_domain,
                    'target': target,
                    'service': service_name,
                    'severity': 'HIGH',
                    'description': f'CNAME points to {service_name} - potential takeover'
                })
                
        # Şüpheli CNAME'ler
        suspicious_patterns = [
            r'\.s3-website-.*\.amazonaws\.com',
            r'\.s3\.amazonaws\.com',
            r'\.cloudfront\.net',
            r'\.github\.io',
            r'\.gitlab\.io',
            r'\.netlify\.app',
            r'\.vercel\.app'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, target):
                results['suspicious_records'].append({
                    'type': 'SUSPICIOUS_CNAME',
                    'domain': source_domain,
                    'target': target,
                    'pattern': pattern,
                    'severity': 'MEDIUM',
                    'description': f'Suspicious CNAME pattern detected'
                })
                
    def detect_suspicious_records(self, results):
        """Şüpheli DNS kayıtlarını tespit et"""
        domain = results['domain']
        
        # TXT kayıtlarında şüpheli içerik
        for txt_record in results['txt_records']:
            value = txt_record['value'].lower()
            
            # GitHub Pages doğrulama
            if 'github-pages' in value or 'github.io' in value:
                results['takeover_indicators'].append({
                    'type': 'GITHUB_TXT',
                    'domain': domain,
                    'record': txt_record,
                    'severity': 'MEDIUM',
                    'description': 'GitHub Pages verification TXT record'
                })
                
            # Cloudflare doğrulama
            if 'cloudflare' in value:
                results['takeover_indicators'].append({
                    'type': 'CLOUDFLARE_TXT',
                    'domain': domain,
                    'record': txt_record,
                    'severity': 'LOW',
                    'description': 'Cloudflare verification TXT record'
                })
                
        # NS kayıtlarında şüpheli nameserver'lar
        suspicious_ns = [
            'github.io',
            'gitlab.io',
            'netlify.app',
            'vercel.app'
        ]
        
        for ns_record in results['ns_records']:
            ns_value = ns_record['value'].lower()
            for suspicious in suspicious_ns:
                if suspicious in ns_value:
                    results['takeover_indicators'].append({
                        'type': 'SUSPICIOUS_NS',
                        'domain': domain,
                        'nameserver': ns_record,
                        'severity': 'HIGH',
                        'description': f'Nameserver points to {suspicious}'
                    })
                    
    def check_takeover_indicators(self, results):
        """Domain takeover göstergelerini kontrol et"""
        domain = results['domain']
        
        # HTTP isteği gönder
        try:
            import requests
            response = requests.get(f"http://{domain}", timeout=10, allow_redirects=True)
            
            if response.status_code == 200:
                content = response.text.lower()
                headers = response.headers
                
                # GitHub Pages kontrolü
                if any(indicator in content for indicator in [
                    'github.io', 'github pages', 'page not found',
                    'there isn\'t a github pages site here',
                    'github-pages'
                ]):
                    results['takeover_indicators'].append({
                        'type': 'HTTP_GITHUB',
                        'domain': domain,
                        'severity': 'HIGH',
                        'description': 'HTTP response indicates GitHub Pages takeover possible'
                    })
                    
                # AWS S3 kontrolü
                if any(indicator in content for indicator in [
                    'no such bucket', 'bucket does not exist',
                    's3-website', 'amazonaws.com'
                ]):
                    results['takeover_indicators'].append({
                        'type': 'HTTP_S3',
                        'domain': domain,
                        'severity': 'HIGH',
                        'description': 'HTTP response indicates S3 bucket takeover possible'
                    })
                    
                # Netlify kontrolü
                if 'netlify' in content and ('not found' in content or '404' in content):
                    results['takeover_indicators'].append({
                        'type': 'HTTP_NETLIFY',
                        'domain': domain,
                        'severity': 'MEDIUM',
                        'description': 'HTTP response indicates Netlify takeover possible'
                    })
                    
        except Exception:
            pass  # HTTP isteği başarısız
            
    def get_domain_info(self, domain):
        """Domain hakkında detaylı bilgi al"""
        info = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'dns_analysis': self.analyze_domain_dns(domain),
            'whois_info': self.get_whois_info(domain),
            'ssl_info': self.get_ssl_info(domain)
        }
        
        return info
        
    def get_whois_info(self, domain):
        """WHOIS bilgilerini al"""
        try:
            import whois
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'status': w.status
            }
        except Exception:
            return {}
            
    def get_ssl_info(self, domain):
        """SSL sertifika bilgilerini al"""
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter']
                    }
        except Exception:
            return {}
            
    def generate_report(self, analysis_results):
        """Analiz raporu oluştur"""
        report = {
            'summary': {
                'total_domains_analyzed': len(analysis_results),
                'total_takeover_indicators': sum(len(r['takeover_indicators']) for r in analysis_results),
                'high_severity': sum(len([i for i in r['takeover_indicators'] if i['severity'] == 'HIGH']) for r in analysis_results),
                'medium_severity': sum(len([i for i in r['takeover_indicators'] if i['severity'] == 'MEDIUM']) for r in analysis_results),
                'low_severity': sum(len([i for i in r['takeover_indicators'] if i['severity'] == 'LOW']) for r in analysis_results)
            },
            'detailed_results': analysis_results,
            'recommendations': self.generate_recommendations(analysis_results)
        }
        
        return report
        
    def generate_recommendations(self, analysis_results):
        """Güvenlik önerileri oluştur"""
        recommendations = []
        
        for result in analysis_results:
            if result['takeover_indicators']:
                recommendations.append({
                    'domain': result['domain'],
                    'issues': len(result['takeover_indicators']),
                    'recommendations': [
                        'Remove or secure CNAME records pointing to third-party services',
                        'Implement proper DNS monitoring',
                        'Use DNS security extensions (DNSSEC)',
                        'Regular security audits of DNS configuration',
                        'Implement proper access controls for DNS management'
                    ]
                })
                
        return recommendations
