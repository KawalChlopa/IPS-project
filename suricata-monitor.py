#!/usr/bin/env python3

import os
import time
import datetime
import argparse
import json
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class SuricataLogHandler(FileSystemEventHandler):
    def __init__(self, output_log=None, check_interval=1.0, log_directory=None, excluded_files=None):
        self.output_log = output_log
        self.check_interval = check_interval
        self.file_positions = {}
        self.log_directory = log_directory or "/var/log/suricata"
        self.excluded_files = excluded_files or []
        
        # Dodaj plik wyjściowy do listy wykluczonych
        if self.output_log and os.path.basename(self.output_log) not in self.excluded_files:
            self.excluded_files.append(os.path.basename(self.output_log))
        
        # Inicjalizacja śledzenia istniejących plików
        self._initialize_files()
    
    def _initialize_files(self):
        """Inicjalizuje śledzenie istniejących plików logów."""
        if os.path.exists(self.log_directory):
            for filename in os.listdir(self.log_directory):
                # Sprawdź, czy plik nie jest na liście wykluczonych
                if filename in self.excluded_files:
                    continue
                    
                if filename.endswith((".log", ".json", ".eve")):
                    filepath = os.path.join(self.log_directory, filename)
                    if os.path.isfile(filepath):
                        self.file_positions[filepath] = os.path.getsize(filepath)
        else:
            print(f"Katalog {self.log_directory} nie istnieje. Sprawdź, czy Suricata jest zainstalowana i skonfigurowana poprawnie.")
    
    def on_modified(self, event):
        if not event.is_directory and (event.src_path.endswith((".log", ".json", ".eve"))):
            # Sprawdź, czy plik nie jest na liście wykluczonych
            if os.path.basename(event.src_path) in self.excluded_files:
                return
            self.process_file(event.src_path)
    
    def on_created(self, event):
        if not event.is_directory and (event.src_path.endswith((".log", ".json", ".eve"))):
            # Sprawdź, czy plik nie jest na liście wykluczonych
            if os.path.basename(event.src_path) in self.excluded_files:
                return
            self.file_positions[event.src_path] = 0
            self.process_file(event.src_path)
    
    def process_file(self, filepath):
        """Przetwarza wszystkie wpisy z pliku logu."""
        # Ignoruj plik wyjściowy, aby uniknąć pętli rekurencyjnej
        if self.output_log and os.path.basename(filepath) == os.path.basename(self.output_log):
            # Aktualizuj tylko pozycję w pliku, ale nie przetwarzaj jego zawartości
            self.file_positions[filepath] = os.path.getsize(filepath)
            return
            
        if filepath not in self.file_positions:
            self.file_positions[filepath] = 0
        
        try:
            file_size = os.path.getsize(filepath)
            if file_size > self.file_positions[filepath]:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(self.file_positions[filepath])
                    new_content = f.read()
                    
                    for line in new_content.splitlines():
                        # Zapisujemy każdy wpis z logów, bez filtrowania
                        self._log_entry(filepath, line)
                
                self.file_positions[filepath] = file_size
        except Exception as e:
            print(f"Błąd podczas przetwarzania pliku {filepath}: {e}")
    
    def _log_entry(self, filepath, line):
        """Zapisuje wykryty wpis do konsoli i pliku logów."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_filename = os.path.basename(filepath)
        log_message = f"[{timestamp}] {log_filename}: {line}"
        
        # Nie zapisuj wpisów z pliku wyjściowego, żeby uniknąć pętli
        if log_filename == os.path.basename(self.output_log):
            return
            
        print(log_message)
        
        if self.output_log:
            try:
                with open(self.output_log, 'a', encoding='utf-8') as output_file:
                    output_file.write(log_message + "\n")
            except Exception as e:
                print(f"Błąd podczas zapisywania do pliku wyjściowego {self.output_log}: {e}")
    
    def check_all_files(self):
        """Sprawdza wszystkie śledzone pliki i wykrywa nowe."""
        # Sprawdzanie istniejących plików
        for filepath in list(self.file_positions.keys()):
            if os.path.exists(filepath):
                self.process_file(filepath)
            else:
                # Usuń z śledzenia pliki, które już nie istnieją
                del self.file_positions[filepath]
        
        # Wykrywanie nowych plików
        if os.path.exists(self.log_directory):
            for filename in os.listdir(self.log_directory):
                # Sprawdź, czy plik nie jest na liście wykluczonych
                if filename in self.excluded_files:
                    continue
                    
                if filename.endswith((".log", ".json", ".eve")):
                    filepath = os.path.join(self.log_directory, filename)
                    if os.path.isfile(filepath) and filepath not in self.file_positions:
                        self.file_positions[filepath] = 0
                        self.process_file(filepath)


def monitor_suricata_logs(output_log=None, check_interval=1.0, log_directory=None, excluded_files=None):
    """Główna funkcja monitorująca logi Suricata."""
    log_dir = log_directory or "/var/log/suricata"
    excluded = excluded_files or []
    
    if not os.path.exists(log_dir):
        print(f"UWAGA: Katalog {log_dir} nie istnieje. Sprawdź, czy Suricata jest zainstalowana i skonfigurowana poprawnie.")
    
    print(f"Rozpoczęcie monitorowania wszystkich logów Suricata w katalogu {log_dir}")
    
    # Zalecane: umieszczanie pliku wyjściowego poza katalogiem monitorowanych logów
    if output_log:
        # Sprawdź, czy plik wyjściowy jest w monitorowanym katalogu
        output_log_abs = os.path.abspath(output_log)
        log_dir_abs = os.path.abspath(log_dir)
        
        if output_log_abs.startswith(log_dir_abs):
            print(f"UWAGA: Plik wyjściowy {output_log} znajduje się w monitorowanym katalogu {log_dir}.")
            print("To może powodować nieskończoną pętlę i powielanie wpisów.")
            print(f"Zalecane jest umieszczenie pliku wyjściowego poza katalogiem monitorowanym.")
            # Automatycznie dodaj plik wyjściowy do wykluczonych
            excluded.append(os.path.basename(output_log))
        
        print(f"Logi będą zapisywane do: {output_log}")
        # Upewnij się, że katalog z plikiem wyjściowym istnieje
        output_dir = os.path.dirname(os.path.abspath(output_log))
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                print(f"Utworzono katalog {output_dir} dla pliku wyjściowego")
            except Exception as e:
                print(f"Błąd podczas tworzenia katalogu {output_dir}: {e}")
                print(f"Logi będą wyświetlane tylko w konsoli")
                output_log = None
    
    # Dodaj "suricata-monitor.log" do wykluczonych plików, aby uniknąć pętli
    if "suricata-monitor.log" not in excluded:
        excluded.append("suricata-monitor.log")
        
    print(f"Wykluczono z monitorowania pliki: {', '.join(excluded)}")
    
    event_handler = SuricataLogHandler(output_log, check_interval, log_dir, excluded)
    observer = Observer()
    
    try:
        observer.schedule(event_handler, path=log_dir, recursive=False)
        observer.start()
        print("Monitoring aktywny. Naciśnij Ctrl+C, aby zatrzymać.")
        
        while True:
            event_handler.check_all_files()
            time.sleep(check_interval)
    except KeyboardInterrupt:
        observer.stop()
        print("\nMonitorowanie zatrzymane")
    except Exception as e:
        print(f"Błąd podczas monitorowania: {e}")
    finally:
        observer.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor logów Suricata")
    parser.add_argument("--output-log", help="Ścieżka do pliku, gdzie będą zapisywane wszystkie logi", default="/var/log/suricata-all/suricata-monitor.log")
    parser.add_argument("--interval", type=float, help="Interwał sprawdzania (w sekundach)", default=1.0)
    parser.add_argument("--log-directory", help="Ścieżka do katalogu z logami Suricata", default="/var/log/suricata")
    parser.add_argument("--exclude", help="Pliki do wykluczenia z monitorowania, oddzielone przecinkami", default="suricata-monitor.log")
    
    args = parser.parse_args()
    excluded_files = [f.strip() for f in args.exclude.split(",") if f.strip()]
    
    # Umieszczenie pliku wyjściowego poza monitorowanym katalogiem
    # domyślnie w osobnym katalogu /var/log/suricata-all/
    monitor_suricata_logs(args.output_log, args.interval, args.log_directory, excluded_files)