import sys
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse, urldefrag
import csv
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QProgressBar, QTextEdit, QCheckBox,
    QSpinBox, QFileDialog, QTabWidget, QStatusBar, QTableWidget, QTableWidgetItem, QListWidget, QAbstractScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject, QTimer
from PyQt6.QtGui import QIcon  # Import QIcon
import socket
import urllib.robotparser
from xml.etree import ElementTree
import time
import re
import json
import networkx as nx
import matplotlib.pyplot as plt
import logging
import os
import multiprocessing
from fake_useragent import UserAgent
import dns.resolver
import whois

class WebCrawler(QObject):
    log_signal = pyqtSignal(str)
    result_signal = pyqtSignal(dict)

    def __init__(self, domain, depth, num_threads, include_subdomains, respect_robots, log_signal, rate_limit=1, proxies=None, auth=None, url_patterns=None, include_dns=False, include_whois=False):
        super().__init__()
        self.domain = domain
        self.depth = depth
        self.num_threads = num_threads
        self.include_subdomains = include_subdomains
        self.respect_robots = respect_robots
        self.visited_urls = set()
        self.results = []
        self.log_signal = log_signal
        self.stop_flag = False
        self.rate_limit = rate_limit if rate_limit is not None else 1
        self.proxies = proxies
        self.auth = auth
        self.url_patterns = url_patterns or []
        self.pause_flag = False
        self.include_dns = include_dns
        self.include_whois = include_whois
        self.robots_parser = urllib.robotparser.RobotFileParser()
        self.robots_parser.set_url(f"http://{self.domain}/robots.txt")
        self.robots_parser.read()

    def start_crawling(self, domains):
        self.stop_flag = False
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            futures = [executor.submit(self.crawl_page, f"http://{domain}", 1) for domain in domains]
            for future in futures:
                future.result()

    def crawl_page(self, url, current_depth):
        while self.pause_flag:
            continue
        if self.stop_flag or current_depth > self.depth or url in self.visited_urls:
            return
        if self.respect_robots and not self.robots_parser.can_fetch('*', url):
            self.log_signal.emit(f"Blocked by robots.txt: {url}")
            return
        self.visited_urls.add(url)

        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            start_time = time.time()
            response = requests.get(url, headers=headers, timeout=3, proxies=self.proxies, auth=self.auth)
            response.raise_for_status()
            load_time = time.time() - start_time

            soup = BeautifulSoup(response.text, 'html.parser')
            internal_links = self.extract_internal_links(soup, url)
            external_links = self.extract_external_links(soup, url)

            # Collect additional information
            forms = self.extract_forms(soup)
            cookies = response.cookies.get_dict()
            js_files = self.extract_js_files(soup)
            security_headers = self.extract_security_headers(response.headers)
            error_messages = self.extract_error_messages(soup)
            emails = self.extract_emails(response.text)
            phone_numbers = self.extract_phone_numbers(response.text)
            meta_tags = self.extract_meta_tags(soup)
            images = self.extract_images(soup)

            # DNS and WHOIS information
            dns_info = self.get_dns_info() if self.include_dns else "Disabled"
            whois_info = self.get_whois_info() if self.include_whois else "Disabled"

            # Log the progress to the GUI
            self.log_signal.emit(f"Crawled {url} with status {response.status_code}")

            # Store the result
            result = {
                'url': url,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'page_title': soup.title.string if soup.title else 'No Title',
                'http_headers': dict(response.headers),
                'forms': forms,
                'cookies': cookies,
                'js_files': js_files,
                'security_headers': security_headers,
                'error_messages': error_messages,
                'emails': emails,
                'phone_numbers': phone_numbers,
                'meta_tags': meta_tags,
                'images': images,
                'internal_links': internal_links,
                'external_links': external_links,
                'load_time': load_time,
                'dns_info': dns_info,
                'whois_info': whois_info
            }
            self.results.append(result)
            self.result_signal.emit(result)

            if current_depth < self.depth:
                with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
                    for link in internal_links:
                        if self.stop_flag:
                            break
                        executor.submit(self.crawl_page, link, current_depth + 1)

        except requests.RequestException as e:
            self.log_signal.emit(f"Error crawling {url}: {e}")
        except socket.gaierror as e:
            self.log_signal.emit(f"Error resolving IP for {url}: {e}")

        time.sleep(self.rate_limit)

    def extract_internal_links(self, soup, base_url):
        links = []
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            href = urldefrag(href)[0]
            full_url = urljoin(base_url, href)
            if self.is_internal_link(full_url):
                links.append(full_url)
        return links

    def extract_external_links(self, soup, base_url):
        links = []
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            href = urldefrag(href)[0]
            full_url = urljoin(base_url, href)
            if not self.is_internal_link(full_url):
                links.append(full_url)
        return links

    def extract_forms(self, soup):
        forms = []
        for form in soup.find_all('form'):
            form_details = {
                'action': form.get('action'),
                'method': form.get('method', 'get').lower(),
                'inputs': [{'name': input_tag.get('name'), 'type': input_tag.get('type', 'text')} for input_tag in form.find_all('input')]
            }
            forms.append(form_details)
        return forms

    def extract_js_files(self, soup):
        js_files = []
        for script in soup.find_all('script', src=True):
            js_files.append(script['src'])
        return js_files

    def extract_security_headers(self, headers):
        security_headers = {}
        required_headers = [
            'Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options',
            'Strict-Transport-Security', 'X-XSS-Protection', 'Referrer-Policy'
        ]
        for header in required_headers:
            security_headers[header] = headers.get(header, 'Missing')
        return security_headers

    def extract_error_messages(self, soup):
        error_messages = []
        for error in soup.find_all(string=True):
            if 'error' in error.lower():
                error_messages.append(error.strip())
        return error_messages

    def extract_emails(self, text):
        return re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)

    def extract_phone_numbers(self, text):
        return re.findall(r"\+?\d[\d -]{8,}\d", text)

    def extract_meta_tags(self, soup):
        meta_tags = {}
        for meta in soup.find_all('meta'):
            name = meta.get('name') or meta.get('property')
            content = meta.get('content')
            if name and content:
                meta_tags[name] = content
        return meta_tags

    def extract_images(self, soup):
        images = []
        for img in soup.find_all('img', src=True):
            images.append(img['src'])
        return images

    def is_internal_link(self, url):
        parsed_url = urlparse(url)
        main_domain = urlparse(f"http://{self.domain}").netloc
        link_domain = parsed_url.netloc
        return main_domain == link_domain or (self.include_subdomains and link_domain.endswith(f".{main_domain}"))

    def get_dns_info(self):
        try:
            answers = dns.resolver.resolve(self.domain, 'A')
            return ', '.join([str(answer) for answer in answers])
        except Exception as e:
            return f"DNS query failed: {e}"

    def get_whois_info(self):
        try:
            domain_info = whois.whois(self.domain)
            return str(domain_info)
        except Exception as e:
            return f"WHOIS lookup failed: {e}"

    def export_to_csv(self, file_name):
        with open(file_name, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['url', 'status_code', 'content_length', 'page_title', 'http_headers', 'forms', 'cookies', 'js_files', 'security_headers', 'error_messages', 'ssl_info', 'load_time', 'dns_info', 'whois_info']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for result in self.results:
                result['emails'] = ', '.join(result.get('emails', []))
                result['phone_numbers'] = ', '.join(result.get('phone_numbers', []))
                writer.writerow(result)

    def export_to_json(self, file_name):
        with open(file_name, 'w', encoding='utf-8') as jsonfile:
            json.dump(self.results, jsonfile, ensure_ascii=False, indent=4)

    def export_to_xml(self, file_name):
        root = ElementTree.Element("results")
        for result in self.results:
            url_elem = ElementTree.SubElement(root, "url")
            for key, value in result.items():
                child = ElementTree.SubElement(url_elem, key)
                child.text = str(value)
        tree = ElementTree.ElementTree(root)
        tree.write(file_name, encoding='utf-8', xml_declaration=True)

    def stop_crawling(self):
        self.stop_flag = True

    def parse_sitemap(self):
        sitemap_url = f"http://{self.domain}/sitemap.xml"
        try:
            response = requests.get(sitemap_url)
            response.raise_for_status()
            tree = ElementTree.fromstring(response.content)
            for elem in tree.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc"):
                url = elem.text
                if self.is_internal_link(url):
                    self.crawl_page(url, 1)
        except requests.RequestException as e:
            self.log_signal.emit(f"Error fetching sitemap: {e}")

    def pause_crawling(self):
        self.pause_flag = True

    def resume_crawling(self):
        self.pause_flag = False

    def visualize_results(self):
        G = nx.Graph()
        for result in self.results:
            G.add_node(result['url'])
        nx.draw(G, with_labels=True)
        plt.show()

class CrawlerThread(QThread):
    log_signal = pyqtSignal(str)
    result_signal = pyqtSignal(dict)

    def __init__(self, domains, depth, num_threads, include_subdomains, respect_robots, user_agent, rate_limit=1, proxies=None, auth=None, url_patterns=None, include_dns=False, include_whois=False):
        super().__init__()
        self.domains = domains
        self.crawler = WebCrawler(
            domains[0], depth, num_threads, include_subdomains, respect_robots,
            self.log_signal, rate_limit, proxies, auth, url_patterns, include_dns, include_whois
        )
        self.crawler.result_signal.connect(self.result_signal)

    def run(self):
        self.crawler.start_crawling(self.domains)

class WebCrawlerGUI(QWidget):
    DOMAIN_LIST_FILE = "domains.txt"
    SETTINGS_FILE = "settings.json"

    def __init__(self):
        super().__init__()

        self.default_size = (400, 600)
        self.setWindowTitle("GoodzyCrawler")
        self.setWindowIcon(QIcon("crawler.png"))  # Set the window icon to crawler.png

        self.load_window_size()

        self.cpu_cores = multiprocessing.cpu_count()

        main_layout = QVBoxLayout()

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        input_layout = QVBoxLayout()
        domain_label = QLabel("Enter Domain:")
        self.domain_input = QLineEdit(self)
        self.add_domain_button = QPushButton("Add Domain")
        self.add_domain_button.clicked.connect(self.add_domain)
        self.upload_button = QPushButton("Upload Domains")
        self.upload_button.clicked.connect(self.upload_domains)
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_domains)
        self.domain_list = QListWidget(self)
        input_layout.addWidget(domain_label)
        input_layout.addWidget(self.domain_input)
        input_layout.addWidget(self.add_domain_button)
        input_layout.addWidget(self.upload_button)
        input_layout.addWidget(self.clear_button)
        input_layout.addWidget(QLabel("Domains List:"))
        input_layout.addWidget(self.domain_list)

        log_layout = QVBoxLayout()
        self.log_area = QTextEdit(self)
        self.log_area.setReadOnly(True)
        log_layout.addWidget(QLabel("Crawl Log"))
        log_layout.addWidget(self.log_area)

        settings_layout = QVBoxLayout()
        settings_label = QLabel("Crawler Settings")
        self.depth_label = QLabel("Crawl Depth:")
        self.depth_spinner = QSpinBox()
        self.depth_spinner.setMinimum(1)
        self.depth_spinner.setMaximum(10)
        self.thread_label = QLabel("Number of Threads:")
        self.thread_spinner = QSpinBox()
        self.thread_spinner.setMinimum(1)
        self.thread_spinner.setMaximum(20)
        self.thread_spinner.setValue(4)
        self.subdomain_checkbox = QCheckBox("Include Subdomains")
        self.robots_checkbox = QCheckBox("Respect robots.txt")
        self.recursive_checkbox = QCheckBox("Recursive Crawling")
        self.user_agent_input = QLineEdit(self)
        self.user_agent_input.setPlaceholderText("Enter User-Agent")
        self.proxy_input = QLineEdit(self)
        self.proxy_input.setPlaceholderText("Enter Proxy (e.g., http://proxy:port)")
        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText("Username")
        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.url_patterns_input = QLineEdit(self)
        self.url_patterns_input.setPlaceholderText("Enter URL patterns (comma-separated)")
        self.rate_limit_input = QSpinBox(self)
        self.rate_limit_input.setMinimum(1)
        self.rate_limit_input.setMaximum(10)
        self.rate_limit_input.setValue(1)
        self.dns_checkbox = QCheckBox("Include DNS Info")
        self.whois_checkbox = QCheckBox("Include WHOIS Info")
        settings_layout.addWidget(settings_label)
        settings_layout.addWidget(self.depth_label)
        settings_layout.addWidget(self.depth_spinner)
        settings_layout.addWidget(self.thread_label)
        settings_layout.addWidget(self.thread_spinner)
        settings_layout.addWidget(self.subdomain_checkbox)
        settings_layout.addWidget(self.robots_checkbox)
        settings_layout.addWidget(self.recursive_checkbox)
        settings_layout.addWidget(QLabel("User-Agent:"))
        settings_layout.addWidget(self.user_agent_input)
        settings_layout.addWidget(QLabel("Proxy:"))
        settings_layout.addWidget(self.proxy_input)
        settings_layout.addWidget(QLabel("Authentication:"))
        settings_layout.addWidget(self.username_input)
        settings_layout.addWidget(self.password_input)
        settings_layout.addWidget(QLabel("URL Patterns:"))
        settings_layout.addWidget(self.url_patterns_input)
        settings_layout.addWidget(QLabel("Rate Limit (seconds):"))
        settings_layout.addWidget(self.rate_limit_input)
        settings_layout.addWidget(self.dns_checkbox)
        settings_layout.addWidget(self.whois_checkbox)

        results_layout = QVBoxLayout()
        self.results_table = QTableWidget(self)
        self.results_table.setColumnCount(17)
        self.results_table.setHorizontalHeaderLabels([
            'URL', 'Status Code', 'Content Length', 'Page Title', 'HTTP Headers',
            'Forms', 'Cookies', 'JS Files', 'Security Headers', 'Error Messages',
            'Emails', 'Phone Numbers', 'Meta Tags', 'Images', 'Load Time', 'DNS Info', 'WHOIS Info'
        ])
        self.results_table.setSizeAdjustPolicy(QAbstractScrollArea.SizeAdjustPolicy.AdjustToContents)
        self.results_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.results_table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        results_layout.addWidget(QLabel("Crawl Results"))
        results_layout.addWidget(self.results_table)

        input_tab = QWidget()
        input_tab.setLayout(input_layout)
        log_tab = QWidget()
        log_tab.setLayout(log_layout)
        settings_tab = QWidget()
        settings_tab.setLayout(settings_layout)
        results_tab = QWidget()
        results_tab.setLayout(results_layout)

        self.tabs.addTab(input_tab, "Input")
        self.tabs.addTab(log_tab, "Logs")
        self.tabs.addTab(settings_tab, "Settings")
        self.tabs.addTab(results_tab, "Results")

        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Crawling")
        self.start_button.clicked.connect(self.start_crawl)
        self.stop_button = QPushButton("Stop Crawling")
        self.stop_button.clicked.connect(self.stop_crawl)
        self.pause_button = QPushButton("Pause Crawling")
        self.pause_button.clicked.connect(self.pause_crawl)
        self.resume_button = QPushButton("Resume Crawling")
        self.resume_button.clicked.connect(self.resume_crawl)
        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self.export_results)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addWidget(self.pause_button)
        button_layout.addWidget(self.resume_button)
        button_layout.addWidget(self.export_button)

        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)

        self.status_bar = QStatusBar(self)
        main_layout.addWidget(self.status_bar)

        self.load_domains()
        self.load_settings()

        self.results_buffer = []
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_results_table)
        self.update_timer.start(1000)

    def load_window_size(self):
        if os.path.exists(self.SETTINGS_FILE):
            with open(self.SETTINGS_FILE, 'r') as f:
                settings = json.load(f)
                width = settings.get('window_width', self.default_size[0])
                height = settings.get('window_height', self.default_size[1])
                self.resize(width, height)
        else:
            self.resize(*self.default_size)

    def save_window_size(self):
        settings = {}
        if os.path.exists(self.SETTINGS_FILE):
            with open(self.SETTINGS_FILE, 'r') as f:
                settings = json.load(f)
        settings['window_width'] = self.width()
        settings['window_height'] = self.height()
        with open(self.SETTINGS_FILE, 'w') as f:
            json.dump(settings, f)

    def closeEvent(self, event):
        self.save_window_size()
        self.save_domains()
        self.save_settings()
        event.accept()

    def add_domain(self):
        domain = self.domain_input.text().strip()
        if domain:
            self.domain_list.addItem(domain)
            self.domain_input.clear()

    def upload_domains(self):
        file_dialog = QFileDialog()
        file_name, _ = file_dialog.getOpenFileName(self, "Open Domain File", "", "Text Files (*.txt);;CSV Files (*.csv)")
        if file_name:
            with open(file_name, 'r') as f:
                domains = f.read().strip().splitlines()
                self.update_domain_list(domains)

    def clear_domains(self):
        self.domain_input.clear()
        self.domain_list.clear()

    def start_crawl(self):
        selected_domains = [item.text() for item in self.domain_list.selectedItems()]
        if not selected_domains:
            self.log_area.append("No domains selected to crawl.")
            return

        recursive = self.recursive_checkbox.isChecked()
        self.log_area.append(f"Starting {'recursive' if recursive else 'non-recursive'} crawl on {', '.join(selected_domains)}")

        depth = self.depth_spinner.value()
        num_threads = self.thread_spinner.value()
        include_subdomains = self.subdomain_checkbox.isChecked()
        respect_robots = self.robots_checkbox.isChecked()
        user_agent = self.user_agent_input.text()
        proxies = None
        auth = None
        url_patterns = self.url_patterns_input.text().split(',')

        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        include_dns = self.dns_checkbox.isChecked()
        include_whois = self.whois_checkbox.isChecked()

        self.crawler_thread = CrawlerThread(
            selected_domains, depth, num_threads, include_subdomains, respect_robots,
            user_agent, rate_limit=1, proxies=proxies, auth=(username, password) if username and password else None,
            url_patterns=url_patterns, include_dns=include_dns, include_whois=include_whois
        )
        self.crawler_thread.log_signal.connect(self.log_area.append)
        self.crawler_thread.result_signal.connect(self.add_result_to_table)
        self.crawler_thread.finished.connect(self.on_crawl_finished)
        self.crawler_thread.start()
        self.status_bar.showMessage("Crawling started...")

    def update_domain_list(self, domains):
        self.domain_list.clear()
        self.domain_list.addItems(domains)

    def stop_crawl(self):
        if self.crawler_thread and self.crawler_thread.isRunning():
            self.crawler_thread.crawler.stop_crawling()
            self.log_area.append("Stopping crawl...")
            self.status_bar.showMessage("Crawling stopped.")

    def on_crawl_finished(self):
        self.log_area.append("Crawling finished.")
        self.status_bar.showMessage("Crawling finished.")

    def update_results_table(self):
        while self.results_buffer:
            result = self.results_buffer.pop(0)
            row_position = self.results_table.rowCount()
            self.results_table.insertRow(row_position)
            self.results_table.setItem(row_position, 0, QTableWidgetItem(result['url']))
            self.results_table.setItem(row_position, 1, QTableWidgetItem(str(result['status_code'])))
            self.results_table.setItem(row_position, 2, QTableWidgetItem(str(result['content_length'])))
            self.results_table.setItem(row_position, 3, QTableWidgetItem(result['page_title']))
            self.results_table.setItem(row_position, 4, QTableWidgetItem(str(result['http_headers'])))
            self.results_table.setItem(row_position, 5, QTableWidgetItem(str(result['forms'])))
            self.results_table.setItem(row_position, 6, QTableWidgetItem(str(result['cookies'])))
            self.results_table.setItem(row_position, 7, QTableWidgetItem(str(result['js_files'])))
            self.results_table.setItem(row_position, 8, QTableWidgetItem(str(result['security_headers'])))
            self.results_table.setItem(row_position, 9, QTableWidgetItem(str(result['error_messages'])))
            self.results_table.setItem(row_position, 10, QTableWidgetItem(', '.join(result['emails'])))
            self.results_table.setItem(row_position, 11, QTableWidgetItem(', '.join(result['phone_numbers'])))
            self.results_table.setItem(row_position, 12, QTableWidgetItem(str(result['meta_tags'])))
            self.results_table.setItem(row_position, 13, QTableWidgetItem(', '.join(result['images'])))
            self.results_table.setItem(row_position, 14, QTableWidgetItem(f"{result['load_time']:.2f} s"))
            self.results_table.setItem(row_position, 15, QTableWidgetItem(result['dns_info']))
            self.results_table.setItem(row_position, 16, QTableWidgetItem(result['whois_info']))

    def export_results(self):
        if self.crawler_thread and self.crawler_thread.crawler.results:
            file_dialog = QFileDialog()
            file_name, _ = file_dialog.getSaveFileName(self, "Save CSV", "", "CSV Files (*.csv)")
            if file_name:
                self.crawler_thread.crawler.export_to_csv(file_name)
                self.log_area.append(f"Results exported to {file_name}")
        else:
            self.log_area.append("No results to export.")

    def pause_crawl(self):
        if self.crawler_thread and self.crawler_thread.isRunning():
            self.crawler_thread.crawler.pause_crawling()
            self.log_area.append("Crawling paused.")
            self.status_bar.showMessage("Crawling paused.")

    def resume_crawl(self):
        if self.crawler_thread and self.crawler_thread.isRunning():
            self.crawler_thread.crawler.resume_crawling()
            self.log_area.append("Crawling resumed.")
            self.status_bar.showMessage("Crawling resumed.")

    def load_domains(self):
        if os.path.exists(self.DOMAIN_LIST_FILE):
            with open(self.DOMAIN_LIST_FILE, 'r') as f:
                domains = f.read().strip().splitlines()
                self.update_domain_list(domains)

    def save_domains(self):
        with open(self.DOMAIN_LIST_FILE, 'w') as f:
            domains = [self.domain_list.item(i).text() for i in range(self.domain_list.count())]
            f.write("\n".join(domains))

    def load_settings(self):
        if os.path.exists(self.SETTINGS_FILE):
            with open(self.SETTINGS_FILE, 'r') as f:
                settings = json.load(f)
                self.depth_spinner.setValue(settings.get('depth', 1))
                self.thread_spinner.setValue(settings.get('num_threads', self.cpu_cores))
                self.subdomain_checkbox.setChecked(settings.get('include_subdomains', False))
                self.robots_checkbox.setChecked(settings.get('respect_robots', False))
                self.recursive_checkbox.setChecked(settings.get('recursive', False))
                self.user_agent_input.setText(settings.get('user_agent', ''))
                self.proxy_input.setText(settings.get('proxy', ''))
                self.username_input.setText(settings.get('username', ''))
                self.password_input.setText(settings.get('password', ''))
                self.url_patterns_input.setText(settings.get('url_patterns', ''))
                self.rate_limit_input.setValue(settings.get('rate_limit', 1))
                self.dns_checkbox.setChecked(settings.get('include_dns', False))
                self.whois_checkbox.setChecked(settings.get('include_whois', False))

    def save_settings(self):
        settings = {
            'depth': self.depth_spinner.value(),
            'num_threads': self.thread_spinner.value(),
            'include_subdomains': self.subdomain_checkbox.isChecked(),
            'respect_robots': self.robots_checkbox.isChecked(),
            'recursive': self.recursive_checkbox.isChecked(),
            'user_agent': self.user_agent_input.text(),
            'proxy': self.proxy_input.text(),
            'username': self.username_input.text(),
            'password': self.password_input.text(),
            'url_patterns': self.url_patterns_input.text(),
            'rate_limit': self.rate_limit_input.value(),
            'include_dns': self.dns_checkbox.isChecked(),
            'include_whois': self.whois_checkbox.isChecked()
        }
        with open(self.SETTINGS_FILE, 'w') as f:
            json.dump(settings, f)

    def add_result_to_table(self, result):
        self.results_buffer.append(result)

def main():
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon("crawler.png"))  # Set the application icon
    window = WebCrawlerGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
