import sys
import re
import email
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser

URL_PATTERN = re.compile(r'https?://[^\s<>"\']+')


def load_eml(filepath):
    with open(filepath, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    return msg


def print_basic_headers(msg):
    print("=== PODSTAWOWE NAGŁÓWKI ===")
    for header in ['From', 'Reply-To', 'Return-Path', 'To', 'Subject', 'Date']:
        value = msg.get(header, '(brak)')
        print(f"{header:12}: {value}")
    print()


def extract_domain(address):
    if not address:
        return None
    _, email_addr = parseaddr(address)
    if '@' not in email_addr:
        return None
    return email_addr.split('@')[-1].lower()


def analyze_discrepancies(msg):
    print("=== ROZBIEŻNOŚCI NADAWCY ===")

    from_domain = extract_domain(msg.get('From'))
    reply_to_domain = extract_domain(msg.get('Reply-To'))
    return_path_domain = extract_domain(msg.get('Return-Path'))

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


def analyze_authentication(msg):
    print("=== UWIERZYTELNIANIE (SPF/DKIM/DMARC) ===")
    auth_headers = msg.get_all('Authentication-Results', [])

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


def analyze_received_path(msg):
    print("=== ŚCIEŻKA RECEIVED (od najnowszego do najstarszego) ===")
    received_headers = msg.get_all('Received', [])

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


def extract_links(msg):
    print("=== ZNALEZIONE LINKI ===")
    all_links = set()

    if msg.is_multipart():
        parts = msg.walk()
    else:
        parts = [msg]

    for part in parts:
        content_type = part.get_content_type()
        if content_type not in ('text/plain', 'text/html'):
            continue

        try:
            content = part.get_content()
        except Exception:
            continue

        if content_type == 'text/html':
            parser = LinkExtractor()
            parser.feed(content)
            all_links.update(parser.links)
            all_links.update(URL_PATTERN.findall(content))
        else:
            all_links.update(URL_PATTERN.findall(content))

    if all_links:
        for link in sorted(all_links):
            print(f"  - {link}")
    else:
        print("  Brak linków.")
    print()


def main():
    if len(sys.argv) != 2:
        print("Użycie: python analiza_eml.py plik.eml")
        sys.exit(1)

    filepath = sys.argv[1]

    try:
        msg = load_eml(filepath)
    except FileNotFoundError:
        print(f"Błąd: nie znaleziono pliku '{filepath}'")
        sys.exit(1)
    except Exception as e:
        print(f"Błąd podczas wczytywania pliku: {e}")
        sys.exit(1)

    print(f"Analiza pliku: {filepath}\n")

    print_basic_headers(msg)
    analyze_discrepancies(msg)
    analyze_authentication(msg)
    analyze_received_path(msg)
    extract_links(msg)


if __name__ == '__main__':
    main()