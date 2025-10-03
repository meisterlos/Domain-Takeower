#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Domain Takeover Scanner
White Hat Security Tool for Domain Takeover Vulnerability Detection
Author: Security Researcher
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import requests
import dns.resolver
import socket
import subprocess
import json
import re
from urllib.parse import urlparse
import concurrent.futures
from datetime import datetime
import os
import sys
from advanced_dns_analyzer import AdvancedDNSAnalyzer

class DomainTakeoverScanner:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Domain Takeover Scanner")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')
        
        # Sonuçları saklamak için
        self.subdomains = []
        self.takeover_vulnerabilities = []
        self.scanning = False
        self.dns_analyzer = AdvancedDNSAnalyzer()
        
        self.setup_ui()
        
    def setup_ui(self):
        # Ana başlık
        title_frame = tk.Frame(self.root, bg='#1e1e1e')
        title_frame.pack(fill='x', padx=10, pady=5)
        
        title_label = tk.Label(title_frame, 
                              text="🔍 Domain Takeover Scanner", 
                              font=('Arial', 16, 'bold'),
                              fg='#00ff00', 
                              bg='#1e1e1e')
        title_label.pack()
        
        subtitle_label = tk.Label(title_frame, 
                                 text="Subdomain Discovery & Domain Takeover Detection",
                                 font=('Arial', 10),
                                 fg='#cccccc', 
                                 bg='#1e1e1e')
        subtitle_label.pack()
        
        # Giriş alanı
        input_frame = tk.Frame(self.root, bg='#2d2d2d', relief='raised', bd=1)
        input_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(input_frame, text="Target Domain:", 
                font=('Arial', 12, 'bold'), 
                fg='white', bg='#2d2d2d').pack(anchor='w', padx=10, pady=5)
        
        self.domain_entry = tk.Entry(input_frame, 
                                    font=('Arial', 12), 
                                    bg='#3d3d3d', 
                                    fg='white',
                                    insertbackground='white',
                                    width=50)
        self.domain_entry.pack(fill='x', padx=10, pady=5)
        
        # Butonlar
        button_frame = tk.Frame(self.root, bg='#1e1e1e')
        button_frame.pack(fill='x', padx=10, pady=5)
        
        self.scan_button = tk.Button(button_frame, 
                                    text="🚀 Start Scan", 
                                    font=('Arial', 12, 'bold'),
                                    bg='#00aa00', 
                                    fg='white',
                                    command=self.start_scan,
                                    width=15)
        self.scan_button.pack(side='left', padx=5)
        
        self.stop_button = tk.Button(button_frame, 
                                    text="⏹ Stop Scan", 
                                    font=('Arial', 12, 'bold'),
                                    bg='#aa0000', 
                                    fg='white',
                                    command=self.stop_scan,
                                    state='disabled',
                                    width=15)
        self.stop_button.pack(side='left', padx=5)
        
        self.export_button = tk.Button(button_frame, 
                                      text="💾 Export Results", 
                                      font=('Arial', 12, 'bold'),
                                      bg='#0066cc', 
                                      fg='white',
                                      command=self.export_results,
                                      width=15)
        self.export_button.pack(side='left', padx=5)
        
        # İlerleme çubuğu
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.root, 
                                           variable=self.progress_var, 
                                           maximum=100,
                                           style='TProgressbar')
        self.progress_bar.pack(fill='x', padx=10, pady=5)
        
        self.status_label = tk.Label(self.root, 
                                    text="Ready to scan...", 
                                    font=('Arial', 10),
                                    fg='#00ff00', 
                                    bg='#1e1e1e')
        self.status_label.pack()
        
        # Sonuç alanları
        results_frame = tk.Frame(self.root, bg='#1e1e1e')
        results_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Notebook (tabbed interface)
        self.notebook = ttk.Notebook(results_frame)
        self.notebook.pack(fill='both', expand=True)
        
        # Subdomain keşfi sekmesi
        subdomain_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.notebook.add(subdomain_frame, text="🔍 Subdomain Discovery")
        
        self.subdomain_text = scrolledtext.ScrolledText(subdomain_frame, 
                                                        bg='#1e1e1e', 
                                                        fg='#00ff00',
                                                        font=('Consolas', 10),
                                                        wrap='word')
        self.subdomain_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Domain takeover sekmesi
        takeover_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.notebook.add(takeover_frame, text="⚠️ Domain Takeover Vulnerabilities")
        
        self.takeover_text = scrolledtext.ScrolledText(takeover_frame, 
                                                      bg='#1e1e1e', 
                                                      fg='#ff4444',
                                                      font=('Consolas', 10),
                                                      wrap='word')
        self.takeover_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # DNS Analizi sekmesi
        dns_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.notebook.add(dns_frame, text="🔍 Advanced DNS Analysis")
        
        self.dns_text = scrolledtext.ScrolledText(dns_frame, 
                                                 bg='#1e1e1e', 
                                                 fg='#00ffff',
                                                 font=('Consolas', 10),
                                                 wrap='word')
        self.dns_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # İstatistikler sekmesi
        stats_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.notebook.add(stats_frame, text="📊 Statistics")
        
        self.stats_text = scrolledtext.ScrolledText(stats_frame, 
                                                   bg='#1e1e1e', 
                                                   fg='#ffff00',
                                                   font=('Consolas', 10),
                                                   wrap='word')
        self.stats_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Stil ayarları
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook.Tab', background='#3d3d3d', foreground='white')
        style.configure('TProgressbar', background='#00aa00')
        
    def log_message(self, text, color='#00ff00'):
        """Log mesajı ekle"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        message = f"[{timestamp}] {text}\n"
        
        # Subdomain sekmesine ekle
        self.subdomain_text.insert(tk.END, message)
        self.subdomain_text.see(tk.END)
        self.root.update_idletasks()
        
    def log_takeover(self, text, color='#ff4444'):
        """Domain takeover mesajı ekle"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        message = f"[{timestamp}] {text}\n"
        
        self.takeover_text.insert(tk.END, message)
        self.takeover_text.see(tk.END)
        self.root.update_idletasks()
        
    def update_status(self, text):
        """Durum güncelle"""
        self.status_label.config(text=text)
        self.root.update_idletasks()
        
    def update_progress(self, value):
        """İlerleme güncelle"""
        self.progress_var.set(value)
        self.root.update_idletasks()
        
    def start_scan(self):
        """Tarama başlat"""
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain name!")
            return
            
        if self.scanning:
            messagebox.showwarning("Warning", "Scan is already in progress!")
            return
            
        # UI durumunu güncelle
        self.scanning = True
        self.scan_button.config(state='disabled')
        self.stop_button.config(state='normal')
        
        # Sonuçları temizle
        self.subdomains = []
        self.takeover_vulnerabilities = []
        self.subdomain_text.delete(1.0, tk.END)
        self.takeover_text.delete(1.0, tk.END)
        self.dns_text.delete(1.0, tk.END)
        self.stats_text.delete(1.0, tk.END)
        
        # Taramayı thread'de başlat
        scan_thread = threading.Thread(target=self.perform_scan, args=(domain,))
        scan_thread.daemon = True
        scan_thread.start()
        
    def stop_scan(self):
        """Tarama durdur"""
        self.scanning = False
        self.scan_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.update_status("Scan stopped by user")
        
    def perform_scan(self, domain):
        """Ana tarama fonksiyonu"""
        try:
            self.update_status(f"Starting comprehensive scan for: {domain}")
            self.update_progress(0)
            
            # 1. Subdomain keşfi
            self.log_message(f"🔍 Starting subdomain discovery for {domain}")
            self.discover_subdomains(domain)
            
            if not self.scanning:
                return
                
            # 2. Gelişmiş DNS analizi
            self.log_message(f"🔍 Starting advanced DNS analysis...")
            self.perform_advanced_dns_analysis(domain)
            
            if not self.scanning:
                return
                
            # 3. Domain takeover kontrolü
            self.log_message(f"⚠️ Checking for domain takeover vulnerabilities...")
            self.check_domain_takeovers()
            
            if not self.scanning:
                return
                
            # 4. İstatistikleri güncelle
            self.generate_statistics()
            
            self.update_status("Scan completed successfully!")
            self.update_progress(100)
            
        except Exception as e:
            self.log_message(f"❌ Error during scan: {str(e)}", '#ff4444')
            self.update_status("Scan failed!")
        finally:
            self.scanning = False
            self.scan_button.config(state='normal')
            self.stop_button.config(state='disabled')
            
    def discover_subdomains(self, domain):
        """Subdomain keşfi"""
        methods = [
            self.subfinder_scan,
            self.crt_sh_scan,
            self.dns_bruteforce,
            self.common_subdomains,
            self.virustotal_scan
        ]
        
        total_methods = len(methods)
        
        for i, method in enumerate(methods):
            if not self.scanning:
                break
                
            try:
                self.log_message(f"🔍 Running {method.__name__}...")
                method(domain)
                progress = ((i + 1) / total_methods) * 50  # %50'ye kadar
                self.update_progress(progress)
            except Exception as e:
                self.log_message(f"❌ Error in {method.__name__}: {str(e)}", '#ff4444')
                
    def subfinder_scan(self, domain):
        """Subfinder ile tarama"""
        try:
            # Subfinder komutunu çalıştır
            cmd = f"subfinder -d {domain} -silent"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                subdomains = result.stdout.strip().split('\n')
                for subdomain in subdomains:
                    if subdomain and subdomain not in self.subdomains:
                        self.subdomains.append(subdomain)
                        self.log_message(f"✅ Found: {subdomain}")
            else:
                self.log_message(f"⚠️ Subfinder not available, skipping...")
                
        except subprocess.TimeoutExpired:
            self.log_message("⚠️ Subfinder scan timed out")
        except FileNotFoundError:
            self.log_message("⚠️ Subfinder not found, skipping...")
        except Exception as e:
            self.log_message(f"❌ Subfinder error: {str(e)}", '#ff4444')
            
    def crt_sh_scan(self, domain):
        """crt.sh API ile tarama"""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for cert in data:
                    if 'name_value' in cert:
                        names = cert['name_value'].split('\n')
                        for name in names:
                            name = name.strip()
                            if name and name not in self.subdomains:
                                self.subdomains.append(name)
                                self.log_message(f"✅ Found: {name}")
                                
        except Exception as e:
            self.log_message(f"❌ crt.sh error: {str(e)}", '#ff4444')
            
    def virustotal_scan(self, domain):
        """VirusTotal API ile tarama"""
        try:
            # VirusTotal API key gerekli (opsiyonel)
            # API key olmadan da çalışır ama limitli
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {
                'apikey': '',  # API key buraya
                'domain': domain
            }
            
            if params['apikey']:  # API key varsa
                response = requests.get(url, params=params, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    if 'subdomains' in data:
                        for subdomain in data['subdomains']:
                            if subdomain not in self.subdomains:
                                self.subdomains.append(subdomain)
                                self.log_message(f"✅ Found: {subdomain}")
            else:
                self.log_message("⚠️ VirusTotal API key not configured, skipping...")
                
        except Exception as e:
            self.log_message(f"❌ VirusTotal error: {str(e)}", '#ff4444')
            
    def dns_bruteforce(self, domain):
        """DNS bruteforce ile tarama"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
            'api', 'blog', 'shop', 'app', 'mobile', 'cdn', 'static',
            'assets', 'images', 'img', 'css', 'js', 'downloads',
            'support', 'help', 'docs', 'wiki', 'forum', 'community',
            'login', 'auth', 'secure', 'ssl', 'vpn', 'remote',
            'backup', 'db', 'database', 'mysql', 'postgres', 'redis',
            'monitor', 'stats', 'analytics', 'logs', 'status',
            'beta', 'alpha', 'demo', 'sandbox', 'playground'
        ]
        
        for subdomain in common_subdomains:
            if not self.scanning:
                break
                
            full_domain = f"{subdomain}.{domain}"
            try:
                result = socket.gethostbyname(full_domain)
                if full_domain not in self.subdomains:
                    self.subdomains.append(full_domain)
                    self.log_message(f"✅ Found: {full_domain} -> {result}")
            except socket.gaierror:
                pass  # Domain bulunamadı
            except Exception as e:
                pass
                
    def common_subdomains(self, domain):
        """Yaygın subdomain listesi ile tarama"""
        wordlist = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'prod',
            'api', 'blog', 'shop', 'app', 'mobile', 'cdn', 'static', 'assets',
            'images', 'img', 'css', 'js', 'downloads', 'files', 'uploads',
            'support', 'help', 'docs', 'wiki', 'forum', 'community', 'chat',
            'login', 'auth', 'secure', 'ssl', 'vpn', 'remote', 'ssh',
            'backup', 'db', 'database', 'mysql', 'postgres', 'redis', 'mongo',
            'monitor', 'stats', 'analytics', 'logs', 'status', 'health',
            'beta', 'alpha', 'demo', 'sandbox', 'playground', 'test2',
            'old', 'new', 'legacy', 'archive', 'temp', 'tmp', 'cache'
        ]
        
        # Paralel DNS lookup
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for subdomain in wordlist:
                if not self.scanning:
                    break
                full_domain = f"{subdomain}.{domain}"
                future = executor.submit(self.check_dns_record, full_domain)
                futures.append(future)
                
            for future in concurrent.futures.as_completed(futures):
                if not self.scanning:
                    break
                try:
                    result = future.result()
                    if result:
                        self.subdomains.append(result)
                        self.log_message(f"✅ Found: {result}")
                except Exception as e:
                    pass
                    
    def check_dns_record(self, domain):
        """DNS kaydı kontrol et"""
        try:
            result = socket.gethostbyname(domain)
            return domain
        except socket.gaierror:
            return None
        except Exception:
            return None
            
    def check_domain_takeovers(self):
        """Domain takeover zafiyetlerini kontrol et"""
        takeover_services = [
            'github.io', 'gitlab.io', 'netlify.app', 'vercel.app',
            'herokuapp.com', 'azurewebsites.net', 'cloudapp.net',
            'amazonaws.com', 's3-website', 's3.amazonaws.com',
            'firebaseapp.com', 'appspot.com', 'tumblr.com',
            'wordpress.com', 'blogspot.com', 'medium.com'
        ]
        
        for subdomain in self.subdomains:
            if not self.scanning:
                break
                
            self.check_single_domain_takeover(subdomain, takeover_services)
            
        self.update_progress(75)
        
    def perform_advanced_dns_analysis(self, domain):
        """Gelişmiş DNS analizi"""
        try:
            self.log_message(f"🔍 Performing advanced DNS analysis for {domain}")
            
            # Ana domain için DNS analizi
            main_domain_info = self.dns_analyzer.get_domain_info(domain)
            self.log_dns_analysis(main_domain_info)
            
            # Bulunan subdomainler için DNS analizi
            for subdomain in self.subdomains[:20]:  # İlk 20 subdomain için
                if not self.scanning:
                    break
                    
                try:
                    subdomain_info = self.dns_analyzer.get_domain_info(subdomain)
                    self.log_dns_analysis(subdomain_info)
                except Exception as e:
                    pass  # Hata durumunda devam et
                    
            self.update_progress(60)
            
        except Exception as e:
            self.log_message(f"❌ DNS analysis error: {str(e)}", '#ff4444')
            
    def log_dns_analysis(self, domain_info):
        """DNS analiz sonuçlarını logla"""
        domain = domain_info['domain']
        dns_analysis = domain_info['dns_analysis']
        
        self.dns_text.insert(tk.END, f"\n{'='*60}\n")
        self.dns_text.insert(tk.END, f"🔍 DNS Analysis for: {domain}\n")
        self.dns_text.insert(tk.END, f"{'='*60}\n")
        
        # DNS kayıtları
        if dns_analysis['a_records']:
            self.dns_text.insert(tk.END, f"\n📍 A Records:\n")
            for record in dns_analysis['a_records']:
                self.dns_text.insert(tk.END, f"  {record['value']} (TTL: {record['ttl']})\n")
                
        if dns_analysis['cname_records']:
            self.dns_text.insert(tk.END, f"\n🔗 CNAME Records:\n")
            for record in dns_analysis['cname_records']:
                self.dns_text.insert(tk.END, f"  {record['value']}\n")
                
        if dns_analysis['mx_records']:
            self.dns_text.insert(tk.END, f"\n📧 MX Records:\n")
            for record in dns_analysis['mx_records']:
                self.dns_text.insert(tk.END, f"  {record['value']}\n")
                
        if dns_analysis['ns_records']:
            self.dns_text.insert(tk.END, f"\n🌐 NS Records:\n")
            for record in dns_analysis['ns_records']:
                self.dns_text.insert(tk.END, f"  {record['value']}\n")
                
        # CNAME zincirleri
        if dns_analysis['cname_chains']:
            self.dns_text.insert(tk.END, f"\n⛓️ CNAME Chains:\n")
            for chain in dns_analysis['cname_chains']:
                chain_str = " -> ".join(chain['chain'])
                self.dns_text.insert(tk.END, f"  {chain_str}\n")
                
        # Takeover göstergeleri
        if dns_analysis['takeover_indicators']:
            self.dns_text.insert(tk.END, f"\n⚠️ Takeover Indicators:\n")
            for indicator in dns_analysis['takeover_indicators']:
                severity_color = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}.get(indicator['severity'], '⚪')
                self.dns_text.insert(tk.END, f"  {severity_color} [{indicator['severity']}] {indicator['description']}\n")
                
        # Şüpheli kayıtlar
        if dns_analysis['suspicious_records']:
            self.dns_text.insert(tk.END, f"\n🚨 Suspicious Records:\n")
            for record in dns_analysis['suspicious_records']:
                self.dns_text.insert(tk.END, f"  🔸 {record['description']}\n")
                
        self.dns_text.see(tk.END)
        self.root.update_idletasks()
        
    def check_single_domain_takeover(self, subdomain, takeover_services):
        """Tek domain için takeover kontrolü"""
        try:
            # HTTP isteği gönder
            url = f"http://{subdomain}"
            response = requests.get(url, timeout=10, allow_redirects=True)
            
            # HTTPS de dene
            if response.status_code != 200:
                url = f"https://{subdomain}"
                response = requests.get(url, timeout=10, allow_redirects=True)
                
            if response.status_code == 200:
                content = response.text.lower()
                headers = response.headers
                
                # GitHub Pages kontrolü
                if any(indicator in content for indicator in [
                    'github.io', 'github pages', 'page not found',
                    'there isn\'t a github pages site here'
                ]):
                    self.takeover_vulnerabilities.append({
                        'domain': subdomain,
                        'service': 'GitHub Pages',
                        'severity': 'HIGH',
                        'description': 'GitHub Pages subdomain takeover possible'
                    })
                    self.log_takeover(f"🚨 HIGH: {subdomain} - GitHub Pages takeover possible")
                    
                # AWS S3 kontrolü
                elif 'no such bucket' in content or 'bucket does not exist' in content:
                    self.takeover_vulnerabilities.append({
                        'domain': subdomain,
                        'service': 'AWS S3',
                        'severity': 'HIGH',
                        'description': 'AWS S3 bucket takeover possible'
                    })
                    self.log_takeover(f"🚨 HIGH: {subdomain} - AWS S3 bucket takeover possible")
                    
                # Netlify kontrolü
                elif 'netlify' in content and 'not found' in content:
                    self.takeover_vulnerabilities.append({
                        'domain': subdomain,
                        'service': 'Netlify',
                        'severity': 'MEDIUM',
                        'description': 'Netlify subdomain takeover possible'
                    })
                    self.log_takeover(f"⚠️ MEDIUM: {subdomain} - Netlify takeover possible")
                    
                # Vercel kontrolü
                elif 'vercel' in content and 'not found' in content:
                    self.takeover_vulnerabilities.append({
                        'domain': subdomain,
                        'service': 'Vercel',
                        'severity': 'MEDIUM',
                        'description': 'Vercel subdomain takeover possible'
                    })
                    self.log_takeover(f"⚠️ MEDIUM: {subdomain} - Vercel takeover possible")
                    
                # Heroku kontrolü
                elif 'heroku' in content and 'no such app' in content:
                    self.takeover_vulnerabilities.append({
                        'domain': subdomain,
                        'service': 'Heroku',
                        'severity': 'HIGH',
                        'description': 'Heroku app takeover possible'
                    })
                    self.log_takeover(f"🚨 HIGH: {subdomain} - Heroku app takeover possible")
                    
        except requests.exceptions.RequestException:
            pass  # Bağlantı hatası
        except Exception as e:
            pass  # Diğer hatalar
            
    def generate_statistics(self):
        """İstatistikleri oluştur"""
        stats = f"""
📊 SCAN STATISTICS
{'='*50}

🎯 Target Domain: {self.domain_entry.get()}
⏰ Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

🔍 SUBDOMAIN DISCOVERY
{'='*50}
Total Subdomains Found: {len(self.subdomains)}

📋 Subdomain List:
{chr(10).join(sorted(set(self.subdomains)))}

⚠️ DOMAIN TAKEOVER VULNERABILITIES
{'='*50}
Total Vulnerabilities: {len(self.takeover_vulnerabilities)}

🚨 HIGH Severity: {len([v for v in self.takeover_vulnerabilities if v['severity'] == 'HIGH'])}
⚠️ MEDIUM Severity: {len([v for v in self.takeover_vulnerabilities if v['severity'] == 'MEDIUM'])}

📋 Vulnerability Details:
"""
        
        for vuln in self.takeover_vulnerabilities:
            stats += f"""
🔸 Domain: {vuln['domain']}
   Service: {vuln['service']}
   Severity: {vuln['severity']}
   Description: {vuln['description']}
   {'-'*40}
"""
        
        self.stats_text.insert(tk.END, stats)
        self.update_progress(100)
        
    def export_results(self):
        """Sonuçları dışa aktar"""
        if not self.subdomains and not self.takeover_vulnerabilities:
            messagebox.showwarning("Warning", "No results to export!")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                results = {
                    'scan_info': {
                        'target_domain': self.domain_entry.get(),
                        'scan_time': datetime.now().isoformat(),
                        'total_subdomains': len(self.subdomains),
                        'total_vulnerabilities': len(self.takeover_vulnerabilities)
                    },
                    'subdomains': sorted(set(self.subdomains)),
                    'vulnerabilities': self.takeover_vulnerabilities
                }
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
                    
                messagebox.showinfo("Success", f"Results exported to: {filename}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {str(e)}")
                
    def run(self):
        """Ana döngüyü başlat"""
        self.root.mainloop()

if __name__ == "__main__":
    try:
        app = DomainTakeoverScanner()
        app.run()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"Error: {str(e)}")
