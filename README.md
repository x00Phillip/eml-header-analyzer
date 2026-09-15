# EML Header Analyzer

Skrypt w Pythonie do szybkiej analizy nagłówków wiadomości e-mail przy triage'u zgłoszeń phishingowych. Automatyzuje sprawdzanie tych samych sygnałów za każdym razem, żeby nic nie zostało pominięte przy ręcznej analizie.

## Obsługiwane formaty

- **`.eml`** — standardowy format RFC822 (Thunderbird, Apple Mail, eksport z większości webmaili)
- **`.txt`** — mail zapisany jako tekst z pełnymi nagłówkami (analizowany identycznie jak `.eml`)
- **`.msg`** — natywny format Outlooka (wymaga dodatkowej biblioteki, patrz niżej)

## Co skrypt sprawdza

- **Podstawowe nagłówki**: From, Reply-To, Return-Path, To, Subject, Date
- **Rozbieżności nadawcy**: porównuje domeny From / Reply-To / Return-Path i oznacza podejrzane różnice
- **Uwierzytelnianie**: wyniki SPF, DKIM i DMARC z nagłówka `Authentication-Results` (wszystkie wystąpienia, jeśli mail przeszedł przez kilka serwerów)
- **Ścieżka Received**: pełna trasa wiadomości przez serwery SMTP, od najnowszego do najstarszego wpisu
- **Linki**: wszystkie URL-e wyciągnięte zarówno z treści HTML (atrybuty `href`), jak i plain text
- **Załączniki**: nazwa, rozmiar oraz hashe MD5/SHA256 (bez zapisywania plików na dysk) — do sprawdzenia np. w VirusTotal

## Wymagania

- Python 3.8+
- Do obsługi `.eml`/`.txt`: tylko standardowa biblioteka Pythona
- Do obsługi `.msg`: biblioteka `extract-msg`

Instalacja zależności:
```bash
pip install -r requirements.txt
```

## Użycie

```bash
python eml-analyzer.py plik.eml
python eml-analyzer.py plik.msg
python eml-analyzer.py plik.txt
```

## Przykładowy output

Analiza pliku: przyklad.eml

=== PODSTAWOWE NAGŁÓWKI ===

From : "IT Support" support@totally-legit-bank[.]com

Reply-To : attacker@random-domain[.]ru

Return-Path : bounce@random-domain[.]ru

To : ofiara@firma[.]pl

Subject : Pilna weryfikacja konta

Date : Mon, 18 Aug 2026 10:15:00 +0000

=== ROZBIEŻNOŚCI NADAWCY ===

From domain: totally-legit-bank[.]com

Reply-To domain: random-domain[.]ru

Return-Path domain: random-domain[.]ru

! PODEJRZANE: Reply-To (random-domain[.]ru) różni się od From (totally-legit-bank[.]com)

! UWAGA: Return-Path (random-domain[.]ru) różni się od From (totally-legit-bank[.]com)

=== UWIERZYTELNIANIE (SPF/DKIM/DMARC) ===

--- Wystąpienie 1 ---

Nagłówek surowy:

spf=fail smtp.mailfrom=random-domain[.]ru; dkim=fail; dmarc=fail

SPF : fail [PODEJRZANE]

DKIM : fail [PODEJRZANE]

DMARC : fail [PODEJRZANE]

=== ŚCIEŻKA RECEIVED (od najnowszego do najstarszego) ===

[Hop 1] from mail[.]firma[.]pl by mx[.]firma[.]pl ...

[Hop 2] from unknown-server[.]ru by mail.firma[.]pl ...

=== ZNALEZIONE LINKI ===

hxxp://totally-legit-bank-verify[.]ru/login

=== ZAŁĄCZNIKI ===

Plik:   faktura.pdf.exe
  
  Rozmiar: 45812 bajtów
  
  MD5:    d41d8cd98f00b204e9800998ecf8427e
  
  SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855



## Ograniczenia

- Skrypt nie odpytuje DNS ani nie weryfikuje SPF/DKIM/DMARC samodzielnie — opiera się na nagłówku `Authentication-Results` dodanym przez serwer odbiorczy. Jeśli ten nagłówek jest fałszowany lub nieobecny, wyniki będą niepełne.
- Część plików `.msg` nie zawiera surowych nagłówków transportowych (np. zapisane szkice) — wtedy SPF/DKIM/DMARC i ścieżka Received będą niedostępne, skrypt to zasygnalizuje.
- Skrypt nie zapisuje załączników na dysk ani nie skanuje ich pod kątem malware — tylko liczy hashe do ręcznej weryfikacji w zewnętrznych bazach.
- Linki są tylko wypisywane do przejrzenia ręcznie / w sandboxie — skrypt nigdy ich nie otwiera.
