#!/usr/bin/env python3
# pcx_builder_dark_fixed_final.py
"""
PCX — Montador de PCs do Brasil (Tema Escuro Gamer) — VERSÃO FINAL
- Correção do erro de 'Part object is not iterable' no Guia de Montagem.
- Adição de botão explícito para Remover Itens da Build.
- Mantidas as correções anteriores (Listas e Inicialização).
"""

import os
import sys
import json
import csv
import sqlite3
import math
import hashlib
import secrets
import threading
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

# Optional scraping libs (tratadas)
HAS_REQUESTS = False
HAS_BS4 = False
try:
    import requests
    HAS_REQUESTS = True
except Exception:
    requests = None
    HAS_REQUESTS = False
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except Exception:
    BeautifulSoup = None
    HAS_BS4 = False

# ----------------------------
# Configurações principais
# ----------------------------
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcx_usuarios.db")
PBKDF2_ITER = 140_000
SALT_BYTES = 16
RESET_TOKEN_TTL_MIN = 15

# Tema de cores (escuro gamer)
THEME_BG = "#0b0f14"        # quase preto
THEME_PANEL = "#0f1720"     # painel
THEME_ACCENT = "#0ea5ff"    # azul neon
THEME_TEXT = "#E6EEF3"      # texto claro
THEME_MUTED = "#94a3b8"     # texto secundário

# ----------------------------
# Funções de banco + segurança
# ----------------------------
def init_db(path=DB_FILE):
    conn = sqlite3.connect(path, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        secret_question TEXT,
        secret_answer_hash TEXT,
        email TEXT,
        created_at TEXT NOT NULL
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        used INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS build_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT,
        bom_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )""")
    conn.commit()
    return conn

def pbkdf2_hash(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITER)
    return dk.hex()

def create_user(conn: sqlite3.Connection, username: str, password: str, email: Optional[str]=None, secret_q: Optional[str]=None, secret_a: Optional[str]=None) -> bool:
    cur = conn.cursor()
    salt = secrets.token_bytes(SALT_BYTES)
    h = pbkdf2_hash(password, salt)
    secret_hash = None
    if secret_a:
        secret_hash = pbkdf2_hash(secret_a.lower(), salt)
    try:
        cur.execute("INSERT INTO users (username,password_hash,salt,secret_question,secret_answer_hash,email,created_at) VALUES (?,?,?,?,?,?,?)",
                    (username, h, salt.hex(), secret_q, secret_hash, email, datetime.utcnow().isoformat()))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def verify_user(conn: sqlite3.Connection, username: str, password: str) -> Optional[int]:
    cur = conn.cursor()
    cur.execute("SELECT id,password_hash,salt FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row:
        return None
    uid, stored_hash, salt_hex = row
    salt = bytes.fromhex(salt_hex)
    cand = pbkdf2_hash(password, salt)
    if secrets.compare_digest(cand, stored_hash):
        return uid
    return None

def request_password_reset(conn: sqlite3.Connection, username_or_email: str) -> Tuple[bool, Optional[str]]:
    cur = conn.cursor()
    cur.execute("SELECT id,email FROM users WHERE username = ? OR email = ?", (username_or_email, username_or_email))
    row = cur.fetchone()
    if not row:
        return False, None
    uid, email = row
    token = secrets.token_urlsafe(24)
    expires = (datetime.utcnow() + timedelta(minutes=RESET_TOKEN_TTL_MIN)).isoformat()
    cur.execute("INSERT INTO reset_tokens (user_id,token,expires_at,used) VALUES (?,?,?,0)", (uid, token, expires))
    conn.commit()
    return True, token

def validate_reset_token(conn: sqlite3.Connection, token: str) -> Optional[int]:
    cur = conn.cursor()
    cur.execute("SELECT id,user_id,expires_at,used FROM reset_tokens WHERE token = ?", (token,))
    row = cur.fetchone()
    if not row:
        return None
    rid, uid, expires_at, used = row
    if used:
        return None
    try:
        if datetime.utcnow() > datetime.fromisoformat(expires_at):
            return None
    except Exception:
        return None
    return uid

def mark_token_used(conn: sqlite3.Connection, token: str):
    cur = conn.cursor()
    cur.execute("UPDATE reset_tokens SET used = 1 WHERE token = ?", (token,))
    conn.commit()

def set_new_password_for_user(conn: sqlite3.Connection, user_id: int, new_password: str):
    cur = conn.cursor()
    salt = secrets.token_bytes(SALT_BYTES)
    h = pbkdf2_hash(new_password, salt)
    cur.execute("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?", (h, salt.hex(), user_id))
    conn.commit()

def get_secret_question(conn: sqlite3.Connection, username: str) -> Optional[str]:
    cur = conn.cursor()
    cur.execute("SELECT secret_question FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    return row[0] if row and row[0] else None 

def verify_secret_answer_and_set(conn: sqlite3.Connection, username: str, answer: str, new_password: str) -> bool:
    cur = conn.cursor()
    cur.execute("SELECT id,secret_answer_hash,salt FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    if not row:
        return False
    uid, secret_hash, salt_hex = row
    if not secret_hash:
        return False 
    salt = bytes.fromhex(salt_hex)
    cand = pbkdf2_hash(answer.lower(), salt)
    if secrets.compare_digest(cand, secret_hash):
        set_new_password_for_user(conn, uid, new_password)
        return True
    return False

def save_build_history(conn: sqlite3.Connection, user_id: int, name: str, bom: dict):
    cur = conn.cursor()
    cur.execute("INSERT INTO build_history (user_id,name,bom_json,created_at) VALUES (?,?,?,?)",
                (user_id, name, json.dumps(bom, ensure_ascii=False), datetime.utcnow().isoformat()))
    conn.commit()

def get_user_builds(conn: sqlite3.Connection, user_id: int) -> List[Dict[str,Any]]:
    cur = conn.cursor()
    cur.execute("SELECT id,name,bom_json,created_at FROM build_history WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    rows = cur.fetchall()
    out = []
    for r in rows:
        try:
            bom_data = json.loads(r[2])
        except json.JSONDecodeError:
            bom_data = {"error": "JSON inválido"}
        out.append({"id": r[0], "name": r[1], "bom": bom_data, "created_at": r[3]})
    return out

# ----------------------------
# Modelos: Part, Catalog, BuildEngine
# ----------------------------
@dataclass
class Part:
    id: str
    category: str
    name: str
    price: float = 0.0
    attributes: Dict[str,Any] = field(default_factory=dict)
    def display(self) -> str:
        p = f"R$ {self.price:.2f}" if self.price else "N/A"
        return f"{self.id} — {self.name} — {p}"

class Catalog:
    def __init__(self):
        self.by_cat: Dict[str,List[Part]] = {}
        self.by_id: Dict[str,Part] = {}
    def add_part(self, p: Part):
        norm_cat = self._normalize_category(p.category)
        p.category = norm_cat
        self.by_cat.setdefault(norm_cat, []).append(p)
        self.by_id[p.id] = p
        
    def _normalize_category(self, cat: str) -> str:
        cat_lower = cat.strip().lower()
        if 'placa-mãe' in cat_lower or 'motherboard' in cat_lower or 'mainboard' in cat_lower:
            return 'Placa-mãe'
        if cat_lower in ('gpu', 'placa de vídeo', 'video card'):
            return 'GPU'
        if cat_lower in ('cpu', 'processador'):
            return 'CPU'
        if cat_lower in ('ram', 'memória'):
            return 'RAM'
        if cat_lower in ('fonte', 'psu', 'power supply'):
            return 'Fonte'
        if cat_lower in ('gabinete', 'case'):
            return 'Gabinete'
        if cat_lower in ('ssd', 'armazenamento', 'hdd', 'storage'):
            return 'Armazenamento'
        if cat_lower in ('cooler', 'aio', 'resfriamento'):
            return 'Cooler'
        return cat.strip()

    def load_csv(self, path, id_col='id', cat_col='category', name_col='name', price_col='price', attrs_col='attributes'):
        with open(path, newline='', encoding='utf-8') as f:
            r = csv.DictReader(f)
            for row in r:
                pid = row.get(id_col) or row.get('sku') or ''
                cat = row.get(cat_col) or 'Unknown'
                name = row.get(name_col) or ''
                price = 0.0
                try: price = float(row.get(price_col)) if row.get(price_col) else 0.0
                except: price = 0.0
                
                attrs = {}
                if attrs_col in row and row[attrs_col]:
                    try: attrs = json.loads(row[attrs_col])
                    except:
                        for k,v in row.items():
                            if k.startswith('attr_') and v:
                                attrs[k[5:]] = _try_num(v)
                for k,v in row.items():
                    if k not in (id_col, cat_col, name_col, price_col, attrs_col) and v:
                        attrs[k] = _try_num(v)

                p = Part(pid, cat, name, price, attrs)
                self.add_part(p)
                
    def load_json(self, path):
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
            arr = data if isinstance(data, list) else data.get('parts', [])
            for it in arr:
                price_val = it.get('price') or it.get('preco') or 0.0
                if isinstance(price_val, str):
                    try: price_val = float(price_val.replace(',','.'))
                    except: price_val = 0.0
                
                p = Part(str(it.get('id','')), 
                         it.get('category') or it.get('categoria') or 'Unknown', 
                         it.get('name') or it.get('nome') or '', 
                         float(price_val), 
                         it.get('attributes') or it.get('atributos') or {})
                self.add_part(p)
                
    def categories(self): return sorted(self.by_cat.keys())
    def parts_in(self, c): return self.by_cat.get(c, [])
    def find(self, pid): return self.by_id.get(pid)

class BuildEngine:
    def __init__(self):
        self.parts: Dict[str,Part] = {}
        self.cat_map = {
            'Placa-mãe': 'Placa-mãe', 'Motherboard': 'Placa-mãe',
            'GPU': 'GPU', 'Placa de Vídeo': 'GPU',
            'CPU': 'CPU', 'Processador': 'CPU',
            'RAM': 'RAM', 'Memória': 'RAM',
            'Fonte': 'Fonte', 'PSU': 'Fonte', 'Power Supply': 'Fonte',
            'Gabinete': 'Gabinete', 'Case': 'Gabinete',
            'Cooler': 'Cooler', 'AIO': 'Cooler', 'Air Cooler': 'Cooler',
            'SSD': 'Armazenamento', 'HDD': 'Armazenamento', 'Armazenamento': 'Armazenamento',
        }
        
    def add(self, p: Part): 
        cat = self.cat_map.get(p.category, p.category)
        self.parts[cat] = p
        
    def remove(self, category: str):
        if category in self.parts: del self.parts[category]
        
    def total_price(self): return sum((p.price or 0.0) for p in self.parts.values())
    
    def estimated_power(self):
        total = 0.0
        for p in self.parts.values():
            tdp = p.attributes.get('tdp_w') or p.attributes.get('tdp') or 0
            try: total += float(tdp)
            except: pass
            
        baseline = 50 
        total += baseline
        rec = int(math.ceil(total * 1.3)) 
        return int(total), rec
    
    def compatibility_issues(self):
        issues = []
        cpu = self.parts.get('CPU')
        mb = self.parts.get('Placa-mãe')
        ram = self.parts.get('RAM')
        gpu = self.parts.get('GPU')
        case = self.parts.get('Gabinete')
        psu = self.parts.get('Fonte')
        cooler = self.parts.get('Cooler')
        
        if cpu and mb:
            cpu_sock = cpu.attributes.get('soquete') or cpu.attributes.get('socket')
            mb_sock = mb.attributes.get('soquete') or mb.attributes.get('socket')
            if cpu_sock and mb_sock and cpu_sock != mb_sock:
                issues.append(f"Soquete incompatível: CPU({cpu_sock}) != Placa-mãe({mb_sock})")
            reqb = cpu.attributes.get('required_bios') or cpu.attributes.get('bios_note')
            if reqb: issues.append(f"Aviso BIOS: {reqb}")

        if ram and mb:
            ram_t = ram.attributes.get('tipo') or ram.attributes.get('mem_type') or ram.attributes.get('type')
            mb_t = mb.attributes.get('mem_type') or mb.attributes.get('ram_type')
            if ram_t and mb_t and ram_t.upper() != mb_t.upper():
                issues.append(f"Tipo de RAM incompatível: {ram_t.upper()} != {mb_t.upper()}")
                
        if gpu and case:
            gl = gpu.attributes.get('comprimento_mm') or gpu.attributes.get('length_mm')
            cm = case.attributes.get('gpu_max_mm') or case.attributes.get('max_gpu_length_mm')
            try:
                if gl and cm and float(gl) > float(cm):
                    issues.append(f"GPU muito longa: {gl}mm > gabinete {cm}mm")
            except: pass

        if cooler and case:
            ch = cooler.attributes.get('height_mm') or cooler.attributes.get('altura_mm')
            clearance = case.attributes.get('cooler_clearance_mm') or case.attributes.get('max_cooler_height_mm')
            try:
                if ch and clearance and float(ch) > float(clearance):
                    issues.append(f"Cooler muito alto: {ch}mm > clearance {clearance}mm")
            except: pass
            
        if psu:
            watt = psu.attributes.get('watt') or psu.attributes.get('power_w')
            _, rec = self.estimated_power()
            try:
                if watt and int(watt) < rec:
                    issues.append(f"Fonte pode ser insuficiente: {watt}W < recomendado {rec}W")
            except: pass
            
        return issues
        
    def assembly_steps(self):
        steps = []
        steps.append("Ferramentas: chave Phillips #2, pasta térmica, pulseira antiestática (opcional).")
        
        # Pega a peça de armazenamento (Objeto unico, nao lista)
        storage = self.parts.get('Armazenamento')
        
        # Fora do Gabinete (Placa-mãe)
        if self.parts.get('Placa-mãe'):
            steps.append("1) Preparação da Placa-mãe: Coloque a placa em cima da caixa antiestática.")
            if self.parts.get('CPU'):
                steps.append("2) Instalar CPU na placa-mãe: Alinhar o triângulo/seta, levantar a alavanca e fechar com cuidado.")
            if self.parts.get('Cooler'):
                steps.append("3) Instalar cooler/AIO e aplicar pasta térmica se necessário (ou se não pré-aplicada).")
            if self.parts.get('RAM'):
                steps.append("4) Inserir módulos de RAM nos slots corretos (consultar manual da placa-mãe para dual channel).")
            
            # CORREÇÃO: Checa M.2 sem iterar
            if storage and str(storage.attributes.get('form_factor', '')).lower() == 'm.2':
                steps.append("5) Instalar SSD M.2 nos slots da placa-mãe e parafusar com cuidado.")
        else:
             steps.append("1) Instalar CPU e Cooler (se for o caso) antes de encaixar a Placa-mãe.")
             if self.parts.get('RAM'): steps.append("2) Inserir RAM nos slots da Placa-mãe.")

        # Dentro do Gabinete
        if self.parts.get('Fonte'):
            steps.append("6) Instalar Fonte no compartimento e rotear os cabos principais (CPU/24pinos) por trás da placa-mãe.")
        if self.parts.get('Placa-mãe'):
            steps.append("7) Instalar Placa-mãe nos 'standoffs' (espaçadores) do gabinete e parafusar com cuidado.")
            
        # CORREÇÃO: Checa SATA sem iterar
        if storage:
            ff = str(storage.attributes.get('form_factor', '')).lower()
            if ff == '2.5' or ff == '3.5' or ff == 'sata':
                steps.append("8) Instalar drive SATA (SSD/HDD) nas baias e conectar cabos de dados (SATA) e energia.")
        
        if self.parts.get('GPU'):
            steps.append("9) Instalar GPU no slot PCIe x16 (geralmente o de cima) e conectar cabos PCIe de energia (se necessário).")
            
        steps.append("10) Conectar cabos frontais (Power/Reset, USB, Áudio) e organizar todos os cabos com abraçadeiras.")
        steps.append("11) Conectar periféricos (Monitor, Teclado, Mouse) e ligar o sistema para o POST inicial.")

        issues = self.compatibility_issues()
        if issues:
            steps.insert(0, "⚠ Atenção: Foram detectados problemas de compatibilidade — reveja antes de ligar:")
            steps[1:1] = [f" - {it}" for it in issues]
            
        return steps
        
    def bom(self):
        return {cat: {"id":p.id, "name":p.name, "price":p.price, "attributes":p.attributes} for cat,p in self.parts.items()}

# ----------------------------
# Helpers
# ----------------------------
def _parse_price_brl(text: str) -> float:
    if not text: return 0.0
    txt = text.strip().replace("\n"," ").replace(" ","")
    txt = txt.replace("R$","").replace("r$","")
    allowed = set("0123456789.,")
    s = "".join(ch for ch in txt if ch in allowed)
    if not s: return 0.0
    if s.count(',') == 1 and s[-3] == ',':
        s = s.replace(".","").replace(",",".")
    elif s.count('.') == 1 and s[-3] == '.':
        pass
    else:
        if s.count('.') > 1: s = s.replace('.', '')
        s = s.replace(',', '.')
    try: return float(s)
    except: return 0.0

def _try_num(v: str):
    try:
        if isinstance(v, (int, float)): return v
        if not isinstance(v, str): return v
        vl = v.strip().lower()
        if not vl: return v
        if vl in ("true", "sim", "yes"): return True
        if vl in ("false", "não", "no"): return False
        vl = vl.replace('gb', '').replace('g', '').replace('tb', '').replace('mhz', '').replace('mm', '').replace('w', '').strip()
        if "." in vl: return float(vl)
        return int(vl)
    except:
        return v
    
# Scrapers omitidos para brevidade, assumindo que funcionam conforme código anterior. 
# Mantendo apenas as chamadas no PCXApp para não quebrar a estrutura.
# (Mantive as definições vazias ou simplificadas se não tiverem sido alteradas, 
# mas no seu caso vou manter o código completo para garantir).

def scrap_kabum_category(url: str, limit: int = 80) -> List[Part]:
    if not (HAS_REQUESTS and HAS_BS4): raise RuntimeError("Libs missing")
    res = requests.get(url, headers={"User-Agent":"pcx-scraper/1.0"})
    soup = BeautifulSoup(res.text, "lxml")
    items = []
    cards = soup.select("[id^=produto-], .productCard, .card-produto, .productCardName, a[href*='/produto/']")
    seen = set()
    for c in cards:
        if c.name == 'a' and c.get('href') and '/produto/' in c.get('href'):
            link = c; href = link["href"]
            name = c.select_one(".name, h2, h3").get_text(" ", strip=True)[:200]
            price_el = c.select_one(".price, .valor, .preco, .productCardPrice")
            price = _parse_price_brl(price_el.get_text() if price_el else None)
        else:
            link = c.find("a", href=True); href = link["href"] if link else None
            name = c.get_text(" ", strip=True)[:200]
            price_el = c.select_one(".price, .valor, .preco")
            price = _parse_price_brl(price_el.get_text() if price_el else None)
        pid = (href.split("/")[-1] if href else f"kb_{len(seen)}")
        if pid in seen: continue
        seen.add(pid)
        cat = "Unknown" # Simplificação
        if "placa de vídeo" in name.lower() or "rtx" in name.lower(): cat = "GPU"
        elif "processador" in name.lower(): cat = "CPU"
        elif "placa-mãe" in name.lower(): cat = "Placa-mãe"
        elif "memória" in name.lower(): cat = "RAM"
        elif "fonte" in name.lower(): cat = "Fonte"
        elif "gabinete" in name.lower(): cat = "Gabinete"
        elif "ssd" in name.lower(): cat = "Armazenamento"
        elif "cooler" in name.lower(): cat = "Cooler"
        items.append(Part(pid, cat, name, price, {"source":"kabum","link":href}))
        if len(items) >= limit: break
    return items

def scrap_pichau_category(url: str, limit: int = 80) -> List[Part]:
    if not (HAS_REQUESTS and HAS_BS4): raise RuntimeError("Libs missing")
    res = requests.get(url, headers={"User-Agent":"pcx-scraper/1.0"})
    soup = BeautifulSoup(res.text, "lxml")
    items = []
    cards = soup.select(".product-card, .produto, .product")
    seen = set()
    for c in cards:
        a = c.find("a", href=True); href = a["href"] if a else None
        name = a.get_text(strip=True) if a else c.get_text(strip=True)[:150]
        price = _parse_price_brl(c.select_one(".price, .valor, .price-box").get_text()) if c.select_one(".price, .valor, .price-box") else 0.0
        pid = href.split("/")[-1] if href else f"pich_{len(seen)}"
        if pid in seen: continue
        seen.add(pid)
        cat = "Unknown"
        if "placa de vídeo" in name.lower() or "rtx" in name.lower(): cat = "GPU"
        elif "processador" in name.lower(): cat = "CPU"
        elif "placa-mãe" in name.lower(): cat = "Placa-mãe"
        elif "memória" in name.lower(): cat = "RAM"
        elif "fonte" in name.lower(): cat = "Fonte"
        elif "gabinete" in name.lower(): cat = "Gabinete"
        elif "ssd" in name.lower(): cat = "Armazenamento"
        elif "cooler" in name.lower(): cat = "Cooler"
        items.append(Part(pid, cat, name, price, {"source":"pichau","link":href}))
        if len(items) >= limit: break
    return items

def scrap_terabyte_category(url: str, limit: int = 80) -> List[Part]:
    if not (HAS_REQUESTS and HAS_BS4): raise RuntimeError("Libs missing")
    res = requests.get(url, headers={"User-Agent":"pcx-scraper/1.0"})
    soup = BeautifulSoup(res.text, "lxml")
    items = []
    cards = soup.select(".product-item, .product")
    seen = set()
    for c in cards:
        a = c.find("a", href=True); href = a["href"] if a else None
        name = a.get_text(strip=True) if a else c.get_text(strip=True)[:150]
        price = _parse_price_brl(c.select_one(".price, .valor").get_text()) if c.select_one(".price, .valor") else 0.0
        pid = href.split("/")[-1] if href else f"ter_{len(seen)}"
        if pid in seen: continue
        seen.add(pid)
        cat = "Unknown"
        if "placa de vídeo" in name.lower() or "rtx" in name.lower(): cat = "GPU"
        elif "processador" in name.lower(): cat = "CPU"
        elif "placa-mãe" in name.lower(): cat = "Placa-mãe"
        elif "memória" in name.lower(): cat = "RAM"
        elif "fonte" in name.lower(): cat = "Fonte"
        elif "gabinete" in name.lower(): cat = "Gabinete"
        elif "ssd" in name.lower(): cat = "Armazenamento"
        elif "cooler" in name.lower(): cat = "Cooler"
        items.append(Part(pid, cat, name, price, {"source":"terabyte","link":href}))
        if len(items) >= limit: break
    return items

# ----------------------------
# UI: Login + PCX App
# ----------------------------
def apply_dark_theme(root: tk.Tk):
    root.configure(bg=THEME_BG)
    style = ttk.Style(root)
    try:
        style.theme_use('clam')
    except:
        pass
    
    style.configure("PCX.TButton", foreground=THEME_TEXT, background=THEME_PANEL, font=("Helvetica", 10, "bold"), relief="flat", borderwidth=0, focusthickness=3)
    style.map("PCX.TButton", background=[('active', THEME_ACCENT), ('!active', THEME_PANEL)], foreground=[('active', THEME_BG), ('!active', THEME_TEXT)])
    
    style.configure("PCX.TLabel", foreground=THEME_TEXT, background=THEME_BG, font=("Helvetica", 10))
    style.configure("PCX.TFrame", background=THEME_PANEL)
    style.configure("PCX.Treeview.Heading", background=THEME_ACCENT, foreground=THEME_BG, font=("Helvetica", 10, "bold"))
    style.configure("PCX.Treeview", background=THEME_PANEL, fieldbackground=THEME_PANEL, foreground=THEME_TEXT, borderwidth=1, relief="solid")
    style.map('PCX.Treeview', background=[('selected', THEME_ACCENT)], foreground=[('selected', THEME_BG)])
    style.configure("PCX.TEntry", fieldbackground=THEME_PANEL, foreground=THEME_TEXT, insertcolor=THEME_ACCENT)

class LoginWindow(tk.Tk):
    def __init__(self, conn):
        super().__init__()
        self.conn = conn
        self.title("PCX — Montador de PCs do Brasil — Login")
        self.geometry("520x360")
        self.resizable(False, False)
        apply_dark_theme(self)
        self._build_ui()

    def _build_ui(self):
        frm = ttk.Frame(self, style="PCX.TFrame", padding=14)
        frm.pack(fill='both', expand=True, padx=12, pady=12)
        login_frame = ttk.Frame(frm, style="PCX.TFrame")
        login_frame.pack(pady=20, padx=20, fill='x')
        
        lbl_user = ttk.Label(login_frame, text="Usuário:", style="PCX.TLabel")
        lbl_user.grid(row=0, column=0, sticky='w', pady=4)
        self.user_entry = ttk.Entry(login_frame, style="PCX.TEntry")
        self.user_entry.grid(row=0, column=1, sticky='ew', padx=6, pady=4)
        
        lbl_pwd = ttk.Label(login_frame, text="Senha:", style="PCX.TLabel")
        lbl_pwd.grid(row=1, column=0, sticky='w', pady=4)
        self.pwd_entry = ttk.Entry(login_frame, show="*", style="PCX.TEntry")
        self.pwd_entry.grid(row=1, column=1, sticky='ew', padx=6, pady=4)
        
        btn_login = ttk.Button(login_frame, text="Entrar", style="PCX.TButton", command=self.on_login)
        btn_login.grid(row=2, column=0, pady=10, sticky='ew', padx=3)
        btn_reg = ttk.Button(login_frame, text="Cadastrar", style="PCX.TButton", command=self.on_register)
        btn_reg.grid(row=2, column=1, pady=10, sticky='ew', padx=3)
        
        login_frame.columnconfigure(1, weight=1)
        login_frame.columnconfigure(0, weight=1)
        ttk.Separator(frm, style="PCX.TFrame").pack(fill='x', pady=8, padx=20)
        
        reset_frame = ttk.Frame(frm, style="PCX.TFrame")
        reset_frame.pack(pady=10, padx=20, fill='x')
        lbl_rec = ttk.Label(reset_frame, text="Recuperar senha:", style="PCX.TLabel")
        lbl_rec.grid(row=0, column=0, sticky='w', pady=4)
        btn_email = ttk.Button(reset_frame, text="Por e-mail (token)", style="PCX.TButton", command=self.on_reset_email)
        btn_email.grid(row=0, column=1, sticky='ew', padx=6, pady=4)
        btn_secret = ttk.Button(reset_frame, text="Por pergunta secreta", style="PCX.TButton", command=self.on_reset_secret)
        btn_secret.grid(row=1, column=1, sticky='ew', padx=6, pady=4)
        note = ttk.Label(frm, text="Dica: recuperação é local — nenhum e-mail será enviado.", style="PCX.TLabel", foreground=THEME_MUTED)
        note.pack(pady=(10,0), padx=20, anchor='w')
        reset_frame.columnconfigure(1, weight=1)
        self.user_entry.focus_set()

    def on_register(self):
        username = self.user_entry.get().strip()
        pwd = self.pwd_entry.get()
        if not username or not pwd:
            messagebox.showwarning("PCX — Cadastro", "Preencha usuário e senha.")
            return
        email = simpledialog.askstring("E-mail (opcional)", "Informe um e-mail para recuperação (opcional):", parent=self)
        sq = simpledialog.askstring("Pergunta secreta (opcional)", "Digite uma pergunta secreta (opcional):", parent=self)
        sa = None
        if sq:
            sa = simpledialog.askstring("Resposta secreta", "Resposta para a pergunta secreta (será guardada em hash):", show="*", parent=self)
            if not sa:
                messagebox.showwarning("PCX — Cadastro", "Resposta secreta vazia — ignorando.")
                sq = None
        ok = create_user(self.conn, username, pwd, email, sq, sa)
        if ok:
            messagebox.showinfo("PCX — Cadastro", "Conta criada com sucesso. Faça login.")
        else:
            messagebox.showerror("PCX — Cadastro", "Usuário já existe. Escolha outro nome.")

    def on_login(self):
        u = self.user_entry.get().strip()
        p = self.pwd_entry.get()
        if not u or not p:
            messagebox.showwarning("PCX — Login", "Preencha usuário e senha.")
            return
        uid = verify_user(self.conn, u, p)
        if uid:
            self.destroy()
            app = PCXApp(self.conn, uid, u)
            app.mainloop()
        else:
            messagebox.showerror("PCX — Login", "Usuário ou senha incorretos.")

    def on_reset_email(self):
        who = simpledialog.askstring("PCX — Redefinição por e-mail", "Informe seu usuário ou e-mail cadastrado:", parent=self)
        if not who: return
        ok, token = request_password_reset(self.conn, who)
        if not ok:
            messagebox.showerror("PCX — Redefinição", "Usuário / e-mail não encontrado.")
            return
        messagebox.showinfo("PCX — Redefinição (simulada)", f"Código temporário: {token}")
        tok = simpledialog.askstring("Token", "Cole o código recebido (ou informado):", parent=self)
        if not tok: return
        uid = validate_reset_token(self.conn, tok)
        if not uid:
            messagebox.showerror("PCX — Redefinição", "Código inválido ou expirado.")
            return
        newpwd = simpledialog.askstring("Nova senha", "Informe a nova senha:", show="*", parent=self)
        if not newpwd: return
        if len(newpwd) < 6:
            messagebox.showerror("PCX — Redefinição", "A senha deve ter pelo menos 6 caracteres.")
            return
        set_new_password_for_user(self.conn, uid, newpwd)
        mark_token_used(self.conn, tok)
        messagebox.showinfo("PCX — Redefinição", "Senha atualizada com sucesso.")

    def on_reset_secret(self):
        user = simpledialog.askstring("PCX — Recuperação por pergunta", "Informe seu usuário:", parent=self)
        if not user: return
        q = get_secret_question(self.conn, user)
        if not q:
            messagebox.showerror("PCX — Recuperação", "Usuário não possui pergunta secreta cadastrada.")
            return
        ans = simpledialog.askstring("PCX — Pergunta secreta", f"{q}\nResposta:", parent=self, show="*")
        if not ans: return
        newpwd = simpledialog.askstring("PCX — Nova senha", "Informe nova senha:", show="*", parent=self)
        if not newpwd: return
        if len(newpwd) < 6:
            messagebox.showerror("PCX — Redefinição", "A senha deve ter pelo menos 6 caracteres.")
            return
        ok = verify_secret_answer_and_set(self.conn, user, ans, newpwd)
        if ok:
            messagebox.showinfo("PCX — Recuperação", "Senha atualizada com sucesso.")
        else:
            messagebox.showerror("PCX — Recuperação", "Resposta incorreta.")

class PCXApp(tk.Tk):
    def __init__(self, conn, user_id:int, username:str):
        super().__init__()
        self.conn = conn
        self.user_id = user_id
        self.username = username
        self.title(f"PCX — Montador de PCs do Brasil — {username}")
        self.geometry("1240x760")
        apply_dark_theme(self)
        self.catalog = Catalog()
        self.build = BuildEngine()
        self._create_ui()
        threading.Thread(target=self._load_sample_catalog).start() 
        self.build_tree.configure(style="PCX.Treeview")

    def _create_ui(self):
        top = ttk.Frame(self, style="PCX.TFrame")
        top.pack(fill='x', padx=8, pady=6)
        ttk.Button(top, text='Carregar CSV', style="PCX.TButton", command=self.load_csv).pack(side='left', padx=4)
        ttk.Button(top, text='Carregar JSON', style="PCX.TButton", command=self.load_json).pack(side='left', padx=4)
        ttk.Button(top, text='Importar KaBuM', style="PCX.TButton", command=self.import_kabum_prompt).pack(side='left', padx=4)
        ttk.Button(top, text='Importar Pichau', style="PCX.TButton", command=self.import_pichau_prompt).pack(side='left', padx=4)
        ttk.Button(top, text='Importar Terabyte', style="PCX.TButton", command=self.import_terabyte_prompt).pack(side='left', padx=4)
        ttk.Button(top, text='Meus Builds', style="PCX.TButton", command=self.show_my_builds).pack(side='right', padx=4)
        ttk.Button(top, text='Salvar Build', style="PCX.TButton", command=self.save_build).pack(side='right', padx=4)

        pan = ttk.PanedWindow(self, orient='horizontal')
        pan.pack(fill='both', expand=True, padx=8, pady=6)
        left = ttk.Frame(pan, style="PCX.TFrame", width=420)
        mid = ttk.Frame(pan, style="PCX.TFrame", width=420)
        right = ttk.Frame(pan, style="PCX.TFrame", width=400)
        pan.add(left, weight=1)
        pan.add(mid, weight=1)
        pan.add(right, weight=1)

        ttk.Label(left, text='⚙ Categorias', style="PCX.TLabel", font=("Helvetica", 12, "bold")).pack(anchor='w', padx=6, pady=(6,0))
        self.cat_list = tk.Listbox(left, height=14, bg=THEME_PANEL, fg=THEME_TEXT, selectbackground=THEME_ACCENT, bd=0, highlightthickness=0, exportselection=False)
        self.cat_list.pack(fill='both', expand=True, padx=6)
        self.cat_list.bind('<<ListboxSelect>>', self.on_cat_select)

        ttk.Label(left, text='📋 Peças (Duplo clique para adicionar)', style="PCX.TLabel", font=("Helvetica", 12, "bold")).pack(anchor='w', padx=6, pady=(8,0))
        self.parts_list = tk.Listbox(left, height=14, bg=THEME_PANEL, fg=THEME_TEXT, selectbackground=THEME_ACCENT, bd=0, highlightthickness=0, exportselection=False)
        self.parts_list.pack(fill='both', expand=True, padx=6, pady=(0,6))
        self.parts_list.bind('<Double-1>', self.on_add_part)

        # --- PAINEL DO MEIO (Build) ---
        ttk.Label(mid, text='💻 Build Atual (Selecione para remover)', style="PCX.TLabel", font=("Helvetica", 12, "bold")).pack(anchor='w', padx=6, pady=(6,0))
        self.build_tree = ttk.Treeview(mid, columns=('cat','name','price'), show='headings', height=20, style="PCX.Treeview")
        self.build_tree.heading('cat', text='Categoria')
        self.build_tree.heading('name', text='Peça')
        self.build_tree.heading('price', text='Preço')
        self.build_tree.column('cat', width=120, anchor='w')
        self.build_tree.column('name', width=200, anchor='w')
        self.build_tree.column('price', width=80, anchor='e')
        self.build_tree.pack(fill='both', expand=True, padx=6, pady=(0,6))
        self.build_tree.bind('<Delete>', self.on_remove)
        
        # BOTÃO DE REMOVER
        ttk.Button(mid, text="Remover Item Selecionado", style="PCX.TButton", command=self.on_remove).pack(anchor='e', padx=6, pady=(0, 6))

        self.total_price_lbl = ttk.Label(mid, text='Total: R$ 0.00', style="PCX.TLabel", font=("Helvetica", 14, "bold"), foreground=THEME_ACCENT)
        self.total_price_lbl.pack(anchor='e', padx=6, pady=(0,6))

        # --- PAINEL DIREITO ---
        ttk.Label(right, text='📟 Console / Guia de Montagem', style="PCX.TLabel", font=("Helvetica", 12, "bold")).pack(anchor='w', padx=6, pady=(6,0))
        btnf = ttk.Frame(right, style="PCX.TFrame")
        btnf.pack(fill='x', pady=6, padx=6)
        ttk.Button(btnf, text='Checar compatibilidade', style="PCX.TButton", command=self.check_compat).pack(side='left', padx=4)
        ttk.Button(btnf, text='Gerar passo-a-passo', style="PCX.TButton", command=self.show_steps).pack(side='left', padx=4)
        ttk.Button(btnf, text='Exportar BOM', style="PCX.TButton", command=self.export_bom).pack(side='left', padx=4)
        self.output = tk.Text(right, height=30, bg=THEME_PANEL, fg=THEME_TEXT, insertbackground=THEME_ACCENT, bd=0, highlightthickness=0)
        self.output.pack(fill='both', expand=True, padx=6, pady=(6,6))

        status = ttk.Label(self, text=f'Logado como: {self.username} — PCX', style="PCX.TLabel", foreground=THEME_MUTED)
        status.pack(side='bottom', fill='x', pady=(0,4), padx=8, anchor='w')
        self.configure(bg=THEME_BG) 

    def _load_sample_catalog(self):
        samples = [
            {"id": "cpu_01", "category": "CPU", "name": "Intel Core i5-12400F", "price": 800.0, "attributes": {"socket": "LGA1700", "tdp_w": 65}},
            {"id": "cpu_02", "category": "CPU", "name": "AMD Ryzen 5 5600", "price": 750.0, "attributes": {"socket": "AM4", "tdp_w": 65}},
            {"id": "mb_01", "category": "Placa-mãe", "name": "ASUS B660 DDR4", "price": 900.0, "attributes": {"socket": "LGA1700", "mem_type": "DDR4", "form_factor": "ATX"}},
            {"id": "mb_02", "category": "Motherboard", "name": "MSI B550M Pro", "price": 750.0, "attributes": {"socket": "AM4", "mem_type": "DDR4", "form_factor": "MicroATX"}},
            {"id": "ram_01", "category": "RAM", "name": "Corsair Vengeance 16GB DDR4 3200MHz", "price": 250.0, "attributes": {"mem_type": "DDR4", "capacidade_gb": 16}},
            {"id": "ram_02", "category": "RAM", "name": "Kingston Fury Beast 32GB DDR5 5600MHz", "price": 450.0, "attributes": {"mem_type": "DDR5", "capacidade_gb": 32}},
            {"id": "gpu_01", "category": "GPU", "name": "RTX 3060 12GB", "price": 1800.0, "attributes": {"length_mm": 280, "tdp_w": 170}},
            {"id": "gpu_02", "category": "Placa de Vídeo", "name": "RX 6600 XT", "price": 1600.0, "attributes": {"length_mm": 260, "tdp_w": 160}},
            {"id": "case_01", "category": "Gabinete", "name": "Corsair 4000D Airflow", "price": 350.0, "attributes": {"gpu_max_mm": 360, "cooler_clearance_mm": 170}},
            {"id": "case_02", "category": "Case", "name": "NZXT H510", "price": 420.0, "attributes": {"gpu_max_mm": 325, "cooler_clearance_mm": 165}},
            {"id": "psu_01", "category": "Fonte", "name": "Corsair RM650 (650W)", "price": 500.0, "attributes": {"watt": 650, "cert": "Gold"}},
            {"id": "psu_02", "category": "Power Supply", "name": "Cooler Master 550W", "price": 380.0, "attributes": {"watt": 550, "cert": "Bronze"}},
            {"id": "ssd_01", "category": "Armazenamento", "name": "Kingston NV2 1TB NVMe", "price": 450.0, "attributes": {"form_factor": "M.2", "mem_type": "NVMe"}},
            {"id": "ssd_02", "category": "SSD", "name": "Crucial MX500 1TB SATA", "price": 400.0, "attributes": {"form_factor": "2.5", "mem_type": "SATA"}},
            {"id": "cooler_01", "category": "Cooler", "name": "Air Cooler Noctua NH-U12S", "price": 350.0, "attributes": {"height_mm": 158}},
            {"id": "cooler_02", "category": "AIO", "name": "Water Cooler Liquid Freezer II 240mm", "price": 600.0, "attributes": {"size_mm": 240}}
        ]
        self.catalog = Catalog()
        for it in samples:
            p = Part(it["id"], it["category"], it["name"], it["price"], it["attributes"])
            self.catalog.add_part(p)
        self._refresh_categories()
        self._refresh_build() 
        self.output.insert('end', "Catálogo completo carregado automaticamente.\n")

    def _refresh_categories(self):
        self.after(0, self._do_refresh_categories)
        
    def _do_refresh_categories(self):
        self.cat_list.delete(0, 'end')
        for c in self.catalog.categories():
            self.cat_list.insert('end', c)
            
    def on_cat_select(self, ev):
        sel = self.cat_list.curselection()
        if not sel: return
        cat = self.cat_list.get(sel[0])
        parts = self.catalog.parts_in(cat)
        self.parts_list.delete(0, 'end')
        for p in parts:
            self.parts_list.insert('end', p.display())

    def on_add_part(self, ev):
        selcat = self.cat_list.curselection()
        if not selcat:
            messagebox.showwarning("PCX", "Selecione uma categoria.")
            return
        cat_name = self.cat_list.get(selcat[0])
        idx = self.parts_list.curselection()
        if not idx:
            messagebox.showwarning("PCX", "Selecione uma peça (duplo clique).")
            return
        disp = self.parts_list.get(idx[0])
        for p in self.catalog.parts_in(cat_name):
            if p.display() == disp:
                self.build.add(p) 
                self._refresh_build()
                self.output.insert('end', f"Adicionada: {p.category} - {p.name}\n")
                self.output.see('end')
                return

    def _refresh_build(self):
        for i in self.build_tree.get_children():
            self.build_tree.delete(i)
        sorted_parts = sorted(self.build.parts.items(), key=lambda item: item[0])
        for cat,p in sorted_parts:
            self.build_tree.insert('', 'end', iid=cat, values=(cat, p.name, f"R$ {p.price:.2f}")) 
        total = self.build.total_price()
        self.total_price_lbl.config(text=f'Total: R$ {total:.2f}')

    def on_remove(self, ev=None):
        sel = self.build_tree.selection()
        for iid in sel:
            cat = iid 
            self.build.remove(cat)
        self._refresh_build()

    def load_csv(self):
        p = filedialog.askopenfilename(filetypes=[("CSV",".csv"),("Todos",".*")], parent=self)
        if not p: return
        try:
            temp_catalog = Catalog()
            temp_catalog.load_csv(p)
            for cat, parts in temp_catalog.by_cat.items():
                for part in parts:
                    self.catalog.add_part(part)
            self._refresh_categories()
            messagebox.showinfo("PCX", f"CSV carregado e {sum(len(v) for v in temp_catalog.by_cat.values())} peças adicionadas/atualizadas.")
        except Exception as e:
            messagebox.showerror("PCX", f"Falha ao carregar CSV: {e}")

    def load_json(self):
        p = filedialog.askopenfilename(filetypes=[("JSON",".json"),("Todos",".*")], parent=self)
        if not p: return
        try:
            temp_catalog = Catalog()
            temp_catalog.load_json(p)
            for cat, parts in temp_catalog.by_cat.items():
                for part in parts:
                    self.catalog.add_part(part)
            self._refresh_categories()
            messagebox.showinfo("PCX", f"JSON carregado e {sum(len(v) for v in temp_catalog.by_cat.values())} peças adicionadas/atualizadas.")
        except Exception as e:
            messagebox.showerror("PCX", f"Falha ao carregar JSON: {e}")

    def _run_scraper(self, scraper_func, url, name):
        def worker():
            try:
                parts = scraper_func(url, limit=200)
                self.after(0, self._handle_scraper_success, parts, name)
            except Exception as e:
                self.after(0, self._handle_scraper_error, e, name)
        threading.Thread(target=worker).start()
        self.output.insert('end', f"Iniciando importação de {name}...\n")
        self.output.see('end')

    def _handle_scraper_success(self, parts, name):
        for p in parts: 
            self.catalog.add_part(p)
        self._refresh_categories()
        messagebox.showinfo("PCX", f"{len(parts)} itens importados do {name}!")
        self.output.insert('end', f"Importação de {name} concluída. {len(parts)} itens adicionados.\n")
        self.output.see('end')

    def _handle_scraper_error(self, e, name):
        messagebox.showerror("PCX", f"Erro ao importar {name}: {e}")
        self.output.insert('end', f"Falha na importação de {name}: {e}\n")
        self.output.see('end')
        
    def import_kabum_prompt(self):
        if not (HAS_REQUESTS and HAS_BS4):
            messagebox.showerror("PCX", "Scraper não disponível. Instale requests + beautifulsoup4 + lxml.")
            return
        url = simpledialog.askstring("Importar KaBuM", "Cole a URL da categoria KaBuM!:", parent=self)
        if url: self._run_scraper(scrap_kabum_category, url, "KaBuM")

    def import_pichau_prompt(self):
        if not (HAS_REQUESTS and HAS_BS4):
            messagebox.showerror("PCX", "Scraper não disponível. Instale requests + beautifulsoup4 + lxml.")
            return
        url = simpledialog.askstring("Importar Pichau", "Cole a URL da categoria Pichau:", parent=self)
        if url: self._run_scraper(scrap_pichau_category, url, "Pichau")

    def import_terabyte_prompt(self):
        if not (HAS_REQUESTS and HAS_BS4):
            messagebox.showerror("PCX", "Scraper não disponível. Instale requests + beautifulsoup4 + lxml.")
            return
        url = simpledialog.askstring("Importar Terabyte", "Cole a URL da categoria Terabyte:", parent=self)
        if url: self._run_scraper(scrap_terabyte_category, url, "Terabyte")
        
    def check_compat(self):
        issues = self.build.compatibility_issues()
        power_usage, power_rec = self.build.estimated_power()
        self.output.insert('end', "\n=== Verificação de compatibilidade e Potência ===\n")
        self.output.insert('end', f"Consumo total estimado: {power_usage}W. Recomendado para a Fonte: {power_rec}W.\n")
        if not issues:
            self.output.insert('end', "✅ Nenhum problema de compatibilidade detectado. (Confirme sempre nos manuais).\n")
        else:
            self.output.insert('end', "⚠ Problemas e Avisos Detectados:\n")
            for it in issues:
                self.output.insert('end', " - " + it + "\n")
        self.output.see('end')

    def show_steps(self):
        try:
            steps = self.build.assembly_steps()
            self.output.insert('end', "\n=== Passo a passo de montagem ===\n")
            for s in steps:
                self.output.insert('end', s + "\n")
            self.output.see('end')
        except Exception as e:
            messagebox.showerror("PCX", f"Erro ao gerar passo-a-passo: {e}")

    def export_bom(self):
        folder = filedialog.askdirectory(parent=self)
        if not folder: return
        csvp = os.path.join(folder, "pcx_bom.csv")
        jsonp = os.path.join(folder, "pcx_bom.json")
        mdp = os.path.join(folder, "pcx_build_guide.md")
        try:
            with open(csvp, "w", newline="", encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(["category","id","name","price","attributes"])
                for cat,p in self.build.parts.items():
                    w.writerow([cat,p.id,p.name,p.price,json.dumps(p.attributes, ensure_ascii=False)])
        except Exception as e:
            messagebox.showerror("PCX - Exportação", f"Falha ao exportar CSV: {e}")
            return
        try:
            with open(jsonp, "w", encoding='utf-8') as f:
                json.dump(self.build.bom(), f, ensure_ascii=False, indent=2)
        except Exception as e:
            messagebox.showerror("PCX - Exportação", f"Falha ao exportar JSON: {e}")
            return
        try:
            with open(mdp, "w", encoding='utf-8') as f:
                f.write("# Guia de Montagem PCX\n\n")
                f.write("## Lista de Peças (BOM)\n")
                for cat, p in self.build.parts.items():
                    f.write(f"* {cat}: {p.name} (R$ {p.price:.2f})\n")
                f.write("\n---\n\n## Passo a Passo\n")
                for s in self.build.assembly_steps():
                    f.write(s + "\n")
        except Exception as e:
            messagebox.showerror("PCX - Exportação", f"Falha ao exportar Guia MD: {e}")
            return
        messagebox.showinfo("PCX", f"BOM e guia exportados com sucesso para {folder}")

    def save_build(self):
        if not self.build.parts:
            messagebox.showwarning("PCX", "O build está vazio. Adicione peças primeiro.")
            return
        name = simpledialog.askstring("Salvar build", "Nome do build (opcional):", parent=self)
        build_name = name.strip() if name and name.strip() else f"Build - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        save_build_history(self.conn, self.user_id, build_name, self.build.bom())
        messagebox.showinfo("PCX", f"Build '{build_name}' salvo no histórico da sua conta.")

    def show_my_builds(self):
        builds = get_user_builds(self.conn, self.user_id)
        if not builds:
            messagebox.showinfo("PCX", "Nenhum build salvo.")
            return
        dlg = tk.Toplevel(self); 
        dlg.title("Meus builds"); 
        dlg.geometry("500x350")
        dlg.configure(bg=THEME_BG)
        tree = ttk.Treeview(dlg, columns=('name','created'), show='headings', style="PCX.Treeview")
        tree.heading('name', text='Nome')
        tree.heading('created', text='Criado em')
        tree.column('name', width=250, anchor='w')
        tree.column('created', width=150, anchor='w')
        tree.pack(fill='both', expand=True, padx=10, pady=10)
        for b in builds:
            try:
                dt = datetime.fromisoformat(b['created_at'])
                created_str = dt.strftime("%d/%m/%Y %H:%M")
            except:
                created_str = b['created_at']
            tree.insert('', 'end', iid=b['id'], values=(b['name'], created_str))
        def on_view(ev):
            sel = tree.selection()
            if not sel: return
            bid = int(sel[0])
            for b in builds:
                if b['id'] == bid:
                    v = tk.Toplevel(dlg); 
                    v.title(f"Build: {b['name']}"); 
                    v.geometry("600x400")
                    v.configure(bg=THEME_BG)
                    t = tk.Text(v, bg=THEME_PANEL, fg=THEME_TEXT, insertbackground=THEME_ACCENT, bd=0, highlightthickness=0)
                    display_text = f"BUILD: {b['name']}\nCriado em: {created_str}\n\n"
                    display_text += "="*50 + "\n"
                    total_price = 0.0
                    for cat, part_data in b['bom'].items():
                        price = part_data.get('price', 0.0)
                        total_price += price
                        display_text += f"Categoria: {cat}\n"
                        display_text += f"Nome: {part_data.get('name', 'N/A')}\n"
                        display_text += f"Preço: R$ {price:.2f}\n"
                        attrs = part_data.get('attributes', {})
                        if attrs:
                            display_text += "Atributos:\n"
                            for k, val in attrs.items():
                                display_text += f"  - {k}: {val}\n"
                        display_text += "-\n"
                    display_text += "="*50 + "\n"
                    display_text += f"PREÇO TOTAL: R$ {total_price:.2f}\n"
                    t.insert('end', display_text)
                    t.config(state=tk.DISABLED)
                    t.pack(fill='both', expand=True, padx=10, pady=10)
                    return
        tree.bind('<Double-1>', on_view)

def main():
    try:
        conn = init_db(DB_FILE)
    except Exception as e:
        tk.Tk().withdraw()
        messagebox.showerror("Erro Fatal", f"Não foi possível inicializar o banco de dados SQLite em {DB_FILE}. Erro: {e}")
        sys.exit(1)
    root = LoginWindow(conn)
    root.mainloop()
    try:
        conn.close()
    except Exception:
        pass

if __name__ == "__main__":
    main()