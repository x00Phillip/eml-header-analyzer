# EML Header Analyzer

Skrypt w Pythonie do szybkiej analizy nagłówków wiadomości e-mail (.eml) przy triage'u zgłoszeń phishingowych. Automatyzuje sprawdzanie tych samych sygnałów za każdym razem, żeby nic nie zostało pominięte przy ręcznej analizie.

## Co skrypt sprawdza

- **Podstawowe nagłówki**: From, Reply-To, Return-Path, To, Subject, Date
- **Rozbieżności nadawcy**: porównuje domeny From / Reply-To / Return-Path i oznacza podejrzane różnice
- **Uwierzytelnianie**: wyniki SPF, DKIM i DMARC z nagłówka `Authentication-Results` (wszystkie wystąpienia, jeśli mail przeszedł przez kilka serwerów)
- **Ścieżka Received**: pełna trasa wiadomości przez serwery SMTP, od najnowszego do najstarszego wpisu
- **Linki**: wszystkie URL-e wyciągnięte zarówno z treści HTML (atrybuty `href`), jak i plain text

## Wymagania

Tylko standardowa biblioteka Pythona (3.8+) — nic nie trzeba instalować przez `pip`.

## Użycie

```bash
python analiza_eml.py plik.eml
```

## Przykładowy output

Analiza pliku: przyklad.eml

=== PODSTAWOWE NAGŁÓWKI ===

From : "IT Support" support@totally-legit-bank.com

Reply-To : attacker@random-domain.ru

Return-Path : bounce@random-domain.ru

To : ofiara@firma.pl

Subject : Pilna weryfikacja konta

Date : Mon, 18 Aug 2026 10:15:00 +0000

=== ROZBIEŻNOŚCI NADAWCY ===

From domain: totally-legit-bank.com

Reply-To domain: random-domain.ru

Return-Path domain: random-domain.ru

! PODEJRZANE: Reply-To (random-domain.ru) różni się od From (totally-legit-bank.com)

! UWAGA: Return-Path (random-domain.ru) różni się od From (totally-legit-bank.com)

=== UWIERZYTELNIANIE (SPF/DKIM/DMARC) ===

--- Wystąpienie 1 ---

Nagłówek surowy:

spf=fail smtp.mailfrom=random-domain.ru; dkim=fail; dmarc=fail

SPF : fail [PODEJRZANE]

DKIM : fail [PODEJRZANE]

DMARC : fail [PODEJRZANE]

=== ŚCIEŻKA RECEIVED (od najnowszego do najstarszego) ===

[Hop 1] from mail.firma.pl by mx.firma.pl ...

[Hop 2] from unknown-server.ru by mail.firma.pl ...

=== ZNALEZIONE LINKI ===

http://totally-legit-bank-verify.ru/login

## Ograniczenia

- Skrypt nie odpytuje DNS ani nie weryfikuje SPF/DKIM/DMARC samodzielnie — opiera się na nagłówku `Authentication-Results` dodanym przez serwer odbiorczy. Jeśli ten nagłówek jest fałszowany lub nieobecny, wyniki będą niepełne.
- Skrypt nie analizuje załączników (np. nie skanuje ich pod kątem malware).
- Linki są tylko wypisywane do przejrzenia ręcznie / w sandboxie — skrypt nigdy ich nie otwiera.