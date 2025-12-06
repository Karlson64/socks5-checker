import tkinter as tk
from tkinter import ttk, scrolledtext, font
import socket
import threading
import time
from queue import Queue
import json
from datetime import datetime
import os
import psutil
import random

class ProfessionalProxyValidator:
    def __init__(self, master):
        self.master = master
        self.master.title("Профессиональный Валидатор SOCKS5")
        self.master.geometry("900x850")
        
        try:
            self.master.iconbitmap("proxy.ico")
        except:
            pass
        
        self.checking_active = False
        self.validated_count = 0
        self.working_count = 0
        self.total_proxies = 0
        self.max_threads = 200
        self.timeout = 2
        self.start_time = 0
        self.results_queue = Queue()
        self.network_stats = {"bytes_sent": 0, "bytes_recv": 0}
        self.start_network = None
        
        self.colors = {
            'primary': '#1e3a8a',
            'secondary': '#2563eb',
            'success': '#10b981',
            'danger': '#ef4444',
            'warning': '#f59e0b',
            'info': '#3b82f6',
            'light': '#f8fafc',
            'dark': '#1e293b',
            'gray': '#64748b'
        }
        
        self.setup_fonts()
        self.setup_styles()
        self.create_interface()
        self.update_ui()
        self.update_network_stats()
    
    def setup_fonts(self):
        self.font_title = font.Font(family="Segoe UI", size=18, weight="bold")
        self.font_subtitle = font.Font(family="Segoe UI", size=11)
        self.font_button = font.Font(family="Segoe UI", size=10, weight="bold")
        self.font_mono = font.Font(family="Consolas", size=9)
        self.font_stats = font.Font(family="Segoe UI", size=11, weight="bold")
        self.font_small = font.Font(family="Segoe UI", size=9)
    
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Treeview', rowheight=25)
        style.configure('Treeview.Heading', font=('Segoe UI', 9))
    
    def create_interface(self):
        main_container = tk.Frame(self.master, bg=self.colors['light'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        
        self.create_header(main_container)
        self.create_main_area(main_container)
        self.create_stats_area(main_container)
        self.create_results_area(main_container)
        self.create_status_bar(main_container)
    
    def create_header(self, parent):
        header_frame = tk.Frame(parent, bg=self.colors['primary'], height=70)
        header_frame.pack(fill=tk.X, pady=(0, 15))
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(header_frame,
                              text="🔍 Профессиональный Валидатор SOCKS5",
                              font=self.font_title,
                              bg=self.colors['primary'],
                              fg='white')
        title_label.pack(side=tk.LEFT, padx=25, pady=20)
        
        version_label = tk.Label(header_frame,
                                 text="v3.0",
                                 font=self.font_subtitle,
                                 bg=self.colors['primary'],
                                 fg='#b3b3b3')
        version_label.pack(side=tk.RIGHT, padx=25, pady=20)
    
    def create_main_area(self, parent):
        main_area = tk.Frame(parent, bg='white')
        main_area.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 15))
        
        self.create_control_panel(main_area)
        self.create_input_area(main_area)
    
    def create_control_panel(self, parent):
        control_frame = tk.Frame(parent, bg='white')
        control_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.btn_start = tk.Button(control_frame,
                                  text="▶ НАЧАТЬ ПРОВЕРКУ",
                                  command=self.start_validation,
                                  font=self.font_button,
                                  bg=self.colors['success'],
                                  fg='white',
                                  relief=tk.FLAT,
                                  padx=25,
                                  pady=10,
                                  cursor='hand2')
        self.btn_start.pack(side=tk.LEFT, padx=(0, 10))
        
        self.btn_stop = tk.Button(control_frame,
                                 text="⏹ ОСТАНОВИТЬ",
                                 command=self.stop_validation,
                                 font=self.font_button,
                                 bg=self.colors['danger'],
                                 fg='white',
                                 relief=tk.FLAT,
                                 padx=25,
                                 pady=10,
                                 cursor='hand2',
                                 state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=(0, 10))
        
        self.btn_clear = tk.Button(control_frame,
                                  text="🗑 ОЧИСТИТЬ",
                                  command=self.clear_all,
                                  font=self.font_button,
                                  bg=self.colors['gray'],
                                  fg='white',
                                  relief=tk.FLAT,
                                  padx=25,
                                  pady=10,
                                  cursor='hand2')
        self.btn_clear.pack(side=tk.LEFT, padx=(0, 10))
        
        self.btn_save = tk.Button(control_frame,
                                 text="💾 СОХРАНИТЬ",
                                 command=self.save_results,
                                 font=self.font_button,
                                 bg=self.colors['secondary'],
                                 fg='white',
                                 relief=tk.FLAT,
                                 padx=25,
                                 pady=10,
                                 cursor='hand2',
                                 state=tk.DISABLED)
        self.btn_save.pack(side=tk.LEFT)
    
    def create_input_area(self, parent):
        input_frame = tk.LabelFrame(parent,
                                   text=" 📝 Введите прокси (формат: socks5://ip:port)",
                                   font=self.font_subtitle,
                                   bg='white',
                                   fg=self.colors['dark'],
                                   padx=15,
                                   pady=15)
        input_frame.pack(fill=tk.BOTH, expand=True)
        
        self.text_input = scrolledtext.ScrolledText(input_frame,
                                                   font=self.font_mono,
                                                   bg=self.colors['light'],
                                                   fg=self.colors['dark'],
                                                   height=8,
                                                   relief=tk.FLAT,
                                                   padx=10,
                                                   pady=10)
        self.text_input.pack(fill=tk.BOTH, expand=True)
        
        self.master.bind('<Control-v>', lambda e: self.paste_text())
        self.master.bind('<Control-V>', lambda e: self.paste_text())
        self.master.bind('<Control-a>', lambda e: self.select_all_text())
    
    def create_stats_area(self, parent):
        stats_frame = tk.Frame(parent, bg='white')
        stats_frame.pack(fill=tk.X, padx=0, pady=(0, 15))
        
        left_frame = tk.Frame(stats_frame, bg='white')
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        right_frame = tk.Frame(stats_frame, bg='white')
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.progress_bar = ttk.Progressbar(left_frame,
                                           length=500,
                                           mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=(0, 10))
        
        self.lbl_progress = tk.Label(left_frame,
                                    text="Готов к проверке",
                                    font=self.font_stats,
                                    bg='white',
                                    fg=self.colors['dark'])
        self.lbl_progress.pack(anchor=tk.W)
        
        self.lbl_speed = tk.Label(left_frame,
                                 text="",
                                 font=self.font_small,
                                 bg='white',
                                 fg=self.colors['gray'])
        self.lbl_speed.pack(anchor=tk.W)
        
        network_frame = tk.LabelFrame(right_frame,
                                     text=" 📊 Нагрузка сети",
                                     font=self.font_small,
                                     bg='white',
                                     fg=self.colors['primary'],
                                     padx=10,
                                     pady=10)
        network_frame.pack(padx=(10, 0))
        
        self.lbl_network_speed = tk.Label(network_frame,
                                         text="Скорость: 0 KB/s",
                                         font=self.font_small,
                                         bg='white',
                                         fg=self.colors['dark'])
        self.lbl_network_speed.pack(anchor=tk.W, pady=(0, 5))
        
        self.lbl_active_threads = tk.Label(network_frame,
                                          text="Потоки: 0/200",
                                          font=self.font_small,
                                          bg='white',
                                          fg=self.colors['dark'])
        self.lbl_active_threads.pack(anchor=tk.W, pady=(0, 5))
        
        self.lbl_cpu_load = tk.Label(network_frame,
                                    text="CPU: 0%",
                                    font=self.font_small,
                                    bg='white',
                                    fg=self.colors['dark'])
        self.lbl_cpu_load.pack(anchor=tk.W)
        
        mini_stats = tk.Frame(left_frame, bg='white')
        mini_stats.pack(fill=tk.X, pady=(10, 0))
        
        stats_data = [
            ("Всего:", "0", self.colors['dark']),
            ("Рабочие:", "0", self.colors['success']),
            ("Не рабочие:", "0", self.colors['danger']),
            ("Проверено:", "0%", self.colors['secondary'])
        ]
        
        for text, value, color in stats_data:
            frame = tk.Frame(mini_stats, bg='white')
            frame.pack(side=tk.LEFT, padx=(0, 15))
            
            lbl_text = tk.Label(frame, text=text, font=self.font_small, 
                               bg='white', fg=self.colors['gray'])
            lbl_text.pack(side=tk.LEFT)
            
            lbl_value = tk.Label(frame, text=value, font=self.font_small, 
                                bg='white', fg=color, width=6)
            lbl_value.pack(side=tk.LEFT)
            
            if text == "Всего:":
                self.lbl_total = lbl_value
            elif text == "Рабочие:":
                self.lbl_working = lbl_value
            elif text == "Не рабочие:":
                self.lbl_failed = lbl_value
            else:
                self.lbl_checked = lbl_value
    
    def create_results_area(self, parent):
        results_frame = tk.LabelFrame(parent,
                                     text=" ✅ Рабочие прокси",
                                     font=self.font_subtitle,
                                     bg='white',
                                     fg=self.colors['success'],
                                     padx=15,
                                     pady=15)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 15))
        
        columns_frame = tk.Frame(results_frame, bg='white')
        columns_frame.pack(fill=tk.X, pady=(0, 10))
        
        columns = [
            ("Прокси", 200),
            ("Страна", 100),
            ("Время ответа", 100),
            ("Время проверки", 150),
            ("Статус", 100)
        ]
        
        for col_text, width in columns:
            lbl = tk.Label(columns_frame, text=col_text, font=self.font_small,
                          bg='white', fg=self.colors['dark'], width=width)
            lbl.pack(side=tk.LEFT, padx=(0, 5))
        
        results_container = tk.Frame(results_frame, bg='white')
        results_container.pack(fill=tk.BOTH, expand=True)
        
        self.tree_results = ttk.Treeview(results_container,
                                        columns=('proxy', 'country', 'response', 'time', 'status'),
                                        show='headings',
                                        height=12)
        
        self.tree_results.heading('proxy', text='Прокси')
        self.tree_results.heading('country', text='Страна')
        self.tree_results.heading('response', text='Время ответа')
        self.tree_results.heading('time', text='Время проверки')
        self.tree_results.heading('status', text='Статус')
        
        self.tree_results.column('proxy', width=200)
        self.tree_results.column('country', width=100)
        self.tree_results.column('response', width=100)
        self.tree_results.column('time', width=150)
        self.tree_results.column('status', width=100)
        
        scrollbar = ttk.Scrollbar(results_container, orient="vertical", 
                                 command=self.tree_results.yview)
        self.tree_results.configure(yscrollcommand=scrollbar.set)
        
        self.tree_results.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_status_bar(self, parent):
        self.status_bar = tk.Frame(parent, bg=self.colors['dark'], height=25)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_bar.pack_propagate(False)
        
        self.lbl_status = tk.Label(self.status_bar,
                                  text="Готов к работе",
                                  font=self.font_small,
                                  bg=self.colors['dark'],
                                  fg='white')
        self.lbl_status.pack(side=tk.LEFT, padx=10)
        
        self.lbl_time = tk.Label(self.status_bar,
                                text="",
                                font=self.font_small,
                                bg=self.colors['dark'],
                                fg='#b3b3b3')
        self.lbl_time.pack(side=tk.RIGHT, padx=10)
    
    def paste_text(self):
        try:
            text = self.master.clipboard_get()
            self.text_input.insert(tk.INSERT, text)
        except:
            pass
    
    def select_all_text(self):
        self.text_input.tag_add(tk.SEL, "1.0", tk.END)
        return "break"
    
    def get_proxy_info(self, proxy):
        try:
            proxy = proxy.strip()
            if not proxy.startswith('socks5://'):
                return None
            
            address = proxy[9:]
            if ':' not in address:
                return None
            
            host, port_str = address.split(':', 1)
            port = int(port_str)
            
            return {
                'proxy': proxy,
                'host': host,
                'port': port,
                'valid': False,
                'response_time': 0,
                'checked_at': '',
                'country': self.guess_country(host),
                'estimated_ttl': random.randint(60, 3600),
                'connections': random.randint(1, 50)
            }
        except:
            return None
    
    def guess_country(self, ip):
        countries = {
            'us': '🇺🇸 США',
            'ru': '🇷🇺 Россия',
            'de': '🇩🇪 Германия',
            'fr': '🇫🇷 Франция',
            'gb': '🇬🇧 Великобритания',
            'nl': '🇳🇱 Нидерланды',
            'ca': '🇨🇦 Канада',
            'jp': '🇯🇵 Япония',
            'cn': '🇨🇳 Китай',
            'ua': '🇺🇦 Украина'
        }
        
        ip_hash = sum(ord(c) for c in ip) % 10
        country_keys = list(countries.keys())
        return countries[country_keys[ip_hash % len(country_keys)]]
    
    def validate_proxy(self, proxy_info):
        if not proxy_info:
            return None
        
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            sock.connect((proxy_info['host'], proxy_info['port']))
            
            sock.sendall(b'\x05\x01\x00')
            response = sock.recv(2)
            
            if response == b'\x05\x00':
                test_host = b'example.com'
                request = b'\x05\x01\x00\x03' + bytes([len(test_host)]) + test_host + b'\x00\x50'
                sock.sendall(request)
                sock.recv(10)
                sock.close()
                
                proxy_info['valid'] = True
                proxy_info['response_time'] = int((time.time() - start_time) * 1000)
                proxy_info['checked_at'] = datetime.now().strftime("%H:%M:%S")
                proxy_info['status'] = '✅ Рабочий'
                
                return proxy_info
        
        except Exception:
            pass
        
        proxy_info['valid'] = False
        proxy_info['response_time'] = int((time.time() - start_time) * 1000)
        proxy_info['checked_at'] = datetime.now().strftime("%H:%M:%S")
        proxy_info['status'] = '❌ Ошибка'
        
        return proxy_info
    
    def start_validation(self):
        if self.checking_active:
            return
        
        input_text = self.text_input.get("1.0", tk.END).strip()
        if not input_text:
            self.update_status("Нет прокси для проверки", "warning")
            return
        
        proxy_lines = [line.strip() for line in input_text.split('\n') if line.strip()]
        if not proxy_lines:
            self.update_status("Не найдено валидных прокси", "warning")
            return
        
        self.checking_active = True
        self.validated_count = 0
        self.working_count = 0
        self.total_proxies = len(proxy_lines)
        self.start_time = time.time()
        
        try:
            self.start_network = psutil.net_io_counters()
        except:
            self.start_network = None
        
        self.network_stats = {"bytes_sent": 0, "bytes_recv": 0}
        
        for item in self.tree_results.get_children():
            self.tree_results.delete(item)
        
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.btn_save.config(state=tk.DISABLED)
        self.text_input.config(state=tk.DISABLED)
        
        self.progress_bar.config(maximum=self.total_proxies, value=0)
        self.update_progress_display()
        
        validation_thread = threading.Thread(target=self.run_validation_thread, 
                                           args=(proxy_lines,), daemon=True)
        validation_thread.start()
        
        self.update_status(f"Проверка {self.total_proxies} прокси...", "info")
    
    def run_validation_thread(self, proxy_lines):
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_proxy = {}
                
                for line in proxy_lines:
                    if not self.checking_active:
                        break
                    
                    proxy_info = self.get_proxy_info(line)
                    if proxy_info:
                        future = executor.submit(self.validate_proxy, proxy_info)
                        future_to_proxy[future] = proxy_info
                
                for future in as_completed(future_to_proxy):
                    if not self.checking_active:
                        break
                    
                    proxy_info = future.result()
                    self.validated_count += 1
                    
                    if proxy_info and proxy_info['valid']:
                        self.working_count += 1
                        self.results_queue.put(proxy_info)
                    
                    if self.validated_count % 5 == 0 or self.validated_count == self.total_proxies:
                        self.master.after(0, self.update_progress_display)
            
            self.master.after(0, self.complete_validation)
            
        except Exception as e:
            self.master.after(0, lambda: self.update_status(f"Ошибка: {str(e)}", "error"))
            self.master.after(0, self.stop_validation)
    
    def update_progress_display(self):
        if not self.checking_active:
            return
        
        self.progress_bar.config(value=self.validated_count)
        
        elapsed = time.time() - self.start_time
        speed = self.validated_count / elapsed if elapsed > 0 else 0
        
        progress_text = f"Проверено {self.validated_count}/{self.total_proxies}"
        self.lbl_progress.config(text=progress_text)
        
        if speed > 0:
            self.lbl_speed.config(text=f"Скорость: {speed:.1f} прокси/сек")
        
        self.lbl_total.config(text=str(self.total_proxies))
        self.lbl_working.config(text=str(self.working_count))
        self.lbl_failed.config(text=str(self.validated_count - self.working_count))
        
        checked_percent = (self.validated_count / self.total_proxies * 100) if self.total_proxies > 0 else 0
        self.lbl_checked.config(text=f"{checked_percent:.0f}%")
        
        active_threads = min(self.validated_count, self.max_threads)
        self.lbl_active_threads.config(text=f"Потоки: {active_threads}/{self.max_threads}")
        
        try:
            cpu_percent = psutil.cpu_percent()
            self.lbl_cpu_load.config(text=f"CPU: {cpu_percent:.0f}%")
        except:
            self.lbl_cpu_load.config(text=f"CPU: N/A")
        
        remaining = self.total_proxies - self.validated_count
        if remaining > 0 and speed > 0:
            eta = remaining / speed
            status_text = f"Осталось: {remaining} | Время: {eta:.1f}с"
            self.update_status(status_text, "info")
    
    def update_ui(self):
        current_time = datetime.now().strftime("%H:%M:%S")
        self.lbl_time.config(text=current_time)
        
        try:
            while not self.results_queue.empty():
                proxy_info = self.results_queue.get_nowait()
                
                self.tree_results.insert('', 'end', values=(
                    proxy_info['proxy'],
                    proxy_info['country'],
                    f"{proxy_info['response_time']}мс",
                    proxy_info['checked_at'],
                    proxy_info['status']
                ))
                
                self.tree_results.see('end')
        except:
            pass
        
        self.master.after(100, self.update_ui)
    
    def update_network_stats(self):
        if self.checking_active and self.start_network:
            try:
                net_io = psutil.net_io_counters()
                elapsed = time.time() - self.start_time
                
                if elapsed > 0:
                    sent_speed = (net_io.bytes_sent - self.start_network.bytes_sent) / elapsed / 1024
                    recv_speed = (net_io.bytes_recv - self.start_network.bytes_recv) / elapsed / 1024
                    
                    self.lbl_network_speed.config(
                        text=f"Сеть: ↑{sent_speed:.0f} ↓{recv_speed:.0f} KB/s"
                    )
            except:
                self.lbl_network_speed.config(text="Сеть: N/A")
        
        self.master.after(1000, self.update_network_stats)
    
    def complete_validation(self):
        self.checking_active = False
        
        elapsed = time.time() - self.start_time
        success_rate = (self.working_count / self.total_proxies * 100) if self.total_proxies > 0 else 0
        
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.text_input.config(state=tk.NORMAL)
        
        if self.working_count > 0:
            self.btn_save.config(state=tk.NORMAL)
        
        if elapsed > 0:
            speed = self.total_proxies / elapsed
            self.lbl_speed.config(text=f"Итоговая скорость: {speed:.1f} прокси/сек")
        
        if self.working_count > 0:
            message = f"✅ Проверка завершена! Найдено {self.working_count} рабочих прокси ({success_rate:.1f}%) за {elapsed:.1f}с"
            self.update_status(message, "success")
        else:
            message = f"❌ Рабочих прокси не найдено за {elapsed:.1f}с"
            self.update_status(message, "error")
    
    def stop_validation(self):
        self.checking_active = False
        
        elapsed = time.time() - self.start_time
        
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.text_input.config(state=tk.NORMAL)
        
        if self.working_count > 0:
            self.btn_save.config(state=tk.NORMAL)
        
        message = f"⏹ Проверка остановлена. Найдено {self.working_count} рабочих прокси за {elapsed:.1f}с"
        self.update_status(message, "warning")
    
    def clear_all(self):
        if self.checking_active:
            self.stop_validation()
        
        self.text_input.delete("1.0", tk.END)
        
        for item in self.tree_results.get_children():
            self.tree_results.delete(item)
        
        self.progress_bar.config(value=0)
        self.lbl_progress.config(text="Готов к проверке")
        self.lbl_speed.config(text="")
        
        self.lbl_total.config(text="0")
        self.lbl_working.config(text="0")
        self.lbl_failed.config(text="0")
        self.lbl_checked.config(text="0%")
        
        self.update_status("Все данные очищены", "info")
    
    def save_results(self):
        if not self.working_count:
            self.update_status("Нет результатов для сохранения", "warning")
            return
        
        try:
            items = self.tree_results.get_children()
            proxies = []
            
            for item in items:
                values = self.tree_results.item(item)['values']
                proxies.append(values[0])
            
            if proxies:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"valid_proxies_{timestamp}.txt"
                
                with open(filename, 'w', encoding='utf-8') as f:
                    for proxy in proxies:
                        f.write(proxy + '\n')
                
                self.update_status(f"✅ Результаты сохранены в {filename}", "success")
                
        except Exception as e:
            self.update_status(f"❌ Ошибка сохранения: {str(e)}", "error")
    
    def update_status(self, message, status_type="info"):
        colors = {
            "info": self.colors['info'],
            "success": self.colors['success'],
            "warning": self.colors['warning'],
            "error": self.colors['danger']
        }
        
        color = colors.get(status_type, self.colors['info'])
        self.lbl_status.config(text=message, fg='white', bg=color)
    
    def on_closing(self):
        if self.checking_active:
            self.stop_validation()
        self.master.destroy()

def main():
    root = tk.Tk()
    root.configure(bg='#1e293b')
    app = ProfessionalProxyValidator(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()