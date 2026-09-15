import sys
import os
import re
import email
import hashlib
from email import policy
from email.message import Message
from email.utils import parseaddr
from html.parser import HTMLParser

try:
    import extract_msg
    HAS_EXTRACT_MSG = True
except ImportError:
    HAS_EXTRACT_MSG = False

URL_PATTERN = re.compile(r'https?://[^\s<>"\']+')


def load_eml(filepath):
    with open(filepath, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    plain_text = ''
    html_text = ''
    attachments = []

    parts = msg.walk() if msg.is_multipart() else [msg]

    for part in parts:
        content_type = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()

        if disposition == 'attachment' or (filename and content_type not in ('text/plain', 'text/html')):
            payload = part.get_payload(decode=True)
            if payload:
                attachments.append((filename or '(bez nazwy)', payload))
            continue

        if content_type not in ('text/plain', 'text/html'):
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        if content_type == 'text/plain':
            plain_text += content
        elif content_type == 'text/html':
            html_text += content

    return msg, plain_text, html_text, attachments


def build_headers_from_fields(msg_obj):
    headers = Message()
    headers['From'] = msg_obj.sender or ''
    headers['To'] = msg_obj.to or ''
    headers['Reply-To'] = getattr(msg_obj, 'replyTo', None) or ''
    headers['Subject'] = msg_obj.subject or ''
    headers['Date'] = str(msg_obj.date) if msg_obj.date else ''
    return headers


def load_msg(filepath):
    if not HAS_EXTRACT_MSG:
        print("Błąd: obsługa plików .msg wymaga biblioteki 'extract-msg'.")
        print("Zainstaluj ją komendą: pip install extract-msg")
        sys.exit(1)

    msg_obj = extract_msg.Message(filepath)

    if msg_obj.header is not None:
        headers = msg_obj.header
    else:
        print("UWAGA: ten plik .msg nie zawiera pełnych surowych nagłówków transportowych.")
        print("       Analiza SPF/DKIM/DMARC i ścieżki Received będzie niedostępna.\n")
        headers = build_headers_from_fields(msg_obj)

    plain_text = msg_obj.body or ''
    html_text = msg_obj.htmlBody or ''
    if isinstance(html_text, bytes):
        html_text = html_text.decode('utf-8', errors='replace')

    attachments = []
    for att in msg_obj.attachments:
        filename = att.longFilename or att.shortFilename or '(bez nazwy)'
        data = att.data
        if data:
            attachments.append((filename, data))

    msg_obj.close()
    return headers, plain_text, html_text, attachments


def load_message(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    if ext == '.msg':
        return load_msg(filepath)
    else:
        return load_eml(filepath)


def print_basic_headers(headers):
    print("=== PODSTAWOWE NAGŁÓWKI ===")
    for header in ['From', 'Reply-To', 'Return-Path', 'To', 'Subject', 'Date']:
        value = headers.get(header, '(brak)')
        print(f"{header:12}: {value}")
    print()


def extract_domain(address):
    if not address:
        return None
    _, email_addr = parseaddr(address)
    if '@' not in email_addr:
        return None
    return email_addr.split('@')[-1].lower()


def analyze_discrepancies(headers):
    print("=== ROZBIEŻNOŚCI NADAWCY ===")

    from_domain = extract_domain(headers.get('From'))
    reply_to_domain = extract_domain(headers.get('Reply-To'))
    return_path_domain = extract_domain(headers.get('Return-Path'))

    print(f"From domain:        {from_domain or '(brak)'}")
    print(f"Reply-To domain:    {reply_to_domain or '(brak)'}")
    print(f"Return-Path domain: {return_path_domain or '(brak)'}")
    print()

    flags = []

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        flags.append(f"PODEJRZANE: Reply-To ({reply_to_domain}) różni się od From ({from_domain})")

    if return_path_domain and from_domain and return_path_domain != from_domain:
        flags.append(f"UWAGA: Return-Path ({return_path_domain}) różni się od From ({from_domain})")

    if flags:
        for f in flags:
            print(f"  ! {f}")
    else:
        print("  Brak rozbieżności między From/Reply-To/Return-Path.")
    print()


def analyze_authentication(headers):
    print("=== UWIERZYTELNIANIE (SPF/DKIM/DMARC) ===")
    auth_headers = headers.get_all('Authentication-Results', [])

    if not auth_headers:
        print("Brak nagłówka Authentication-Results — serwer nie dodał wyniku weryfikacji.")
        print()
        return

    for i, auth_header in enumerate(auth_headers, start=1):
        print(f"--- Wystąpienie {i} ---")
        print(f"Nagłówek surowy:\n{auth_header}\n")

        for mechanism in ['spf', 'dkim', 'dmarc']:
            match = re.search(rf'{mechanism}=(\w+)', auth_header, re.IGNORECASE)
            if match:
                result = match.group(1).lower()
                flag = "OK" if result == 'pass' else "PODEJRZANE" if result in ('fail', 'softfail') else "UWAGA"
                print(f"{mechanism.upper():6}: {result:10} [{flag}]")
            else:
                print(f"{mechanism.upper():6}: brak wyniku")
        print()


def analyze_received_path(headers):
    print("=== ŚCIEŻKA RECEIVED (od najnowszego do najstarszego) ===")
    received_headers = headers.get_all('Received', [])

    if not received_headers:
        print("Brak nagłówków Received.")
        print()
        return

    for i, hop in enumerate(received_headers, start=1):
        clean = ' '.join(hop.split())
        print(f"[Hop {i}] {clean}")
    print()

class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = set()

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for attr_name, attr_value in attrs:
                if attr_name == 'href' and attr_value:
                    self.links.add(attr_value)


def extract_links(plain_text, html_text):
    print("=== ZNALEZIONE LINKI ===")
    all_links = set()

    if html_text:
        parser = LinkExtractor()
        parser.feed(html_text)
        all_links.update(parser.links)
        all_links.update(URL_PATTERN.findall(html_text))

    if plain_text:
        all_links.update(URL_PATTERN.findall(plain_text))

    if all_links:
        for link in sorted(all_links):
            print(f"  - {link}")
    else:
        print("  Brak linków.")
    print()

def analyze_attachments(attachments):
    print("=== ZAŁĄCZNIKI ===")

    if not attachments:
        print("  Brak załączników.")
        print()
        return

    for filename, data in attachments:
        size = len(data)
        md5_hash = hashlib.md5(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()

        print(f"  Plik:   {filename}")
        print(f"  Rozmiar: {size} bajtów")
        print(f"  MD5:    {md5_hash}")
        print(f"  SHA256: {sha256_hash}")
        print()


def main():
    if len(sys.argv) != 2:
        print("Użycie: python analiza_eml.py plik")
        sys.exit(1)

    filepath = sys.argv[1]

    try:
        headers, plain_text, html_text, attachments = load_message(filepath)
    except FileNotFoundError:
        print(f"Błąd: nie znaleziono pliku '{filepath}'")
        sys.exit(1)
    except Exception as e:
        print(f"Błąd podczas wczytywania pliku: {e}")
        sys.exit(1)

    print(f"Analiza pliku: {filepath}\n")

    print_basic_headers(headers)
    analyze_discrepancies(headers)
    analyze_authentication(headers)
    analyze_received_path(headers)
    extract_links(plain_text, html_text)
    analyze_attachments(attachments)

if __name__ == '__main__':
    main()