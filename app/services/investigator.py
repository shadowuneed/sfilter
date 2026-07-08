from __future__ import annotations

import asyncio
import csv
import re
import time
from dataclasses import dataclass, field
from io import StringIO
from threading import Event
from typing import Any
from urllib.parse import urlencode, urljoin

import httpx
from bs4 import BeautifulSoup

from app.config import Settings
from app.database import Database, utc_now
from app.services.domains import (
    extract_domain,
    find_domains,
    is_candidate_domain,
    is_candidate_url,
    is_technical_url,
    likely_related_domains,
    normalize_url,
    registered_domain,
    unwrap_known_redirect_url,
)
from app.services.content_intelligence import ContentIntelligence
from app.services.cyberscan_classifier import CyberScanClassifier
from app.services.evidence import EvidenceCollector, score_finding
from app.services.gemini import GeminiAPIError, GeminiClient, GeminiQuotaError
from app.services.ml_classifier import DomainMLClassifier
from app.services.risky_domains import (
    gambling_domain_signals,
    has_casino_context,
    has_gambling_context,
    has_user_risk_search_context,
)
from app.services.screenshots import ScreenshotService


CYBERSCAN_OSINT_SOURCES = [
    {
        "name": "openphish",
        "url": "https://openphish.com/feed.txt",
        "category": "phishing",
        "parser": "plain_list",
    },
    {
        "name": "urlhaus",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "category": "malware",
        "parser": "csv",
    },
    {
        "name": "phishing_database",
        "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        "category": "phishing",
        "parser": "plain_list",
    },
    {
        "name": "stevenblack_gambling",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts",
        "category": "casino",
        "parser": "hosts_file",
    },
    {
        "name": "stopgambling",
        "url": "https://raw.githubusercontent.com/StopGambling/domain-list/main/domains.txt",
        "category": "casino",
        "parser": "plain_list",
    },
]

BOOTSTRAP_CANDIDATES = [
    {"domain": "1xbet.com", "category": "casino", "brand": "1xBet", "aliases": ["1xbet", "1x bet"]},
    {"domain": "1win.com", "category": "casino", "brand": "1win", "aliases": ["1win", "1 win"]},
    {"domain": "mostbet.com", "category": "casino", "brand": "Mostbet", "aliases": ["mostbet", "most bet"]},
    {"domain": "mostbet-kz.org", "category": "casino", "brand": "Mostbet", "aliases": ["mostbet", "most bet"]},
    {"domain": "pin-up.kz", "category": "casino", "brand": "Pin-Up", "aliases": ["pinup", "pin-up", "pin up"]},
    {"domain": "pin-up.com", "category": "casino", "brand": "Pin-Up", "aliases": ["pinup", "pin-up", "pin up"]},
    {"domain": "olimpbet.kz", "category": "casino", "brand": "Olimpbet", "aliases": ["olimp", "olimpbet"]},
    {"domain": "melbet.com", "category": "casino", "brand": "Melbet", "aliases": ["melbet", "mel bet"]},
    {"domain": "fonbet.kz", "category": "casino", "brand": "Fonbet", "aliases": ["fonbet", "fon bet"]},
    {"domain": "parimatch.kz", "category": "casino", "brand": "Parimatch", "aliases": ["parimatch", "pari match"]},
    {"domain": "bet365.com", "category": "casino", "brand": "Bet365", "aliases": ["bet365", "bet 365"]},
    {"domain": "vavada.com", "category": "casino", "brand": "Vavada", "aliases": ["vavada"]},
    {"domain": "vulkanvegas.com", "category": "casino", "brand": "Vulkan Vegas", "aliases": ["vulkan", "vulkan vegas"]},
    {"domain": "joycasino.com", "category": "casino", "brand": "JoyCasino", "aliases": ["joycasino", "joy casino"]},
    {"domain": "playfortuna.com", "category": "casino", "brand": "Play Fortuna", "aliases": ["playfortuna", "play fortuna"]},
    {"domain": "mrbit.com", "category": "casino", "brand": "Mr Bit", "aliases": ["mrbit", "mr bit"]},
    {"domain": "casinia.com", "category": "casino", "brand": "Casinia", "aliases": ["casinia"]},
    {"domain": "ninecasino.com", "category": "casino", "brand": "NineCasino", "aliases": ["ninecasino", "nine casino"]},
    {"domain": "playamo.com", "category": "casino", "brand": "PlayAmo", "aliases": ["playamo", "play amo"]},
    {"domain": "bitcasino.io", "category": "casino", "brand": "Bitcasino", "aliases": ["bitcasino", "bit casino"]},
    {"domain": "bitstarz.com", "category": "casino", "brand": "BitStarz", "aliases": ["bitstarz", "bit starz"]},
    {"domain": "fortunejack.com", "category": "casino", "brand": "FortuneJack", "aliases": ["fortunejack", "fortune jack"]},
    {"domain": "7bitcasino.com", "category": "casino", "brand": "7BitCasino", "aliases": ["7bitcasino", "7bit casino"]},
    {"domain": "casino-x.com", "category": "casino", "brand": "Casino X", "aliases": ["casino-x", "casino x", "casinox"]},
    {"domain": "boomerang-casino.com", "category": "casino", "brand": "Boomerang Casino", "aliases": ["boomerang casino", "boomerang"]},
    {"domain": "spinanga.com", "category": "casino", "brand": "Spinanga", "aliases": ["spinanga"]},
    {"domain": "nomini.com", "category": "casino", "brand": "Nomini", "aliases": ["nomini"]},
    {"domain": "slottica.com", "category": "casino", "brand": "Slottica", "aliases": ["slottica"]},
    {"domain": "wildz.com", "category": "casino", "brand": "Wildz", "aliases": ["wildz"]},
    {"domain": "n1casino.com", "category": "casino", "brand": "N1 Casino", "aliases": ["n1casino", "n1 casino"]},
    {"domain": "rocketplay.com", "category": "casino", "brand": "RocketPlay", "aliases": ["rocketplay", "rocket play"]},
    {"domain": "hellspin.com", "category": "casino", "brand": "HellSpin", "aliases": ["hellspin", "hell spin"]},
    {"domain": "mystake.com", "category": "casino", "brand": "MyStake", "aliases": ["mystake", "my stake"]},
    {"domain": "ggbet.com", "category": "casino", "brand": "GG.Bet", "aliases": ["ggbet", "gg bet"]},
    {"domain": "stake.com", "category": "casino", "brand": "Stake", "aliases": ["stake"]},
    {"domain": "bc.game", "category": "casino", "brand": "BC.Game", "aliases": ["bcgame", "bc game"]},
    {"domain": "roobet.com", "category": "casino", "brand": "Roobet", "aliases": ["roobet"]},
    {"domain": "rollbit.com", "category": "casino", "brand": "Rollbit", "aliases": ["rollbit"]},
    {"domain": "sportsbet.io", "category": "casino", "brand": "Sportsbet.io", "aliases": ["sportsbet"]},
    {"domain": "cloudbet.com", "category": "casino", "brand": "Cloudbet", "aliases": ["cloudbet"]},
    {"domain": "duelbits.com", "category": "casino", "brand": "Duelbits", "aliases": ["duelbits"]},
    {"domain": "bitsler.com", "category": "casino", "brand": "Bitsler", "aliases": ["bitsler"]},
    {"domain": "22bet.com", "category": "casino", "brand": "22Bet", "aliases": ["22bet", "22 bet"]},
    {"domain": "betwinner.com", "category": "casino", "brand": "Betwinner", "aliases": ["betwinner"]},
    {"domain": "linebet.com", "category": "casino", "brand": "Linebet", "aliases": ["linebet"]},
    {"domain": "megapari.com", "category": "casino", "brand": "Megapari", "aliases": ["megapari"]},
    {"domain": "rabona.com", "category": "casino", "brand": "Rabona", "aliases": ["rabona"]},
    {"domain": "spinbetter.com", "category": "casino", "brand": "SpinBetter", "aliases": ["spinbetter", "spin better"]},
    {"domain": "betway.com", "category": "casino", "brand": "Betway", "aliases": ["betway"]},
    {"domain": "betfair.com", "category": "casino", "brand": "Betfair", "aliases": ["betfair"]},
    {"domain": "unibet.com", "category": "casino", "brand": "Unibet", "aliases": ["unibet"]},
    {"domain": "bwin.com", "category": "casino", "brand": "Bwin", "aliases": ["bwin"]},
    {"domain": "betano.com", "category": "casino", "brand": "Betano", "aliases": ["betano"]},
    {"domain": "pokerstars.com", "category": "casino", "brand": "PokerStars", "aliases": ["pokerstars", "poker stars"]},
    {"domain": "888casino.com", "category": "casino", "brand": "888casino", "aliases": ["888casino", "888 casino"]},
    {"domain": "leovegas.com", "category": "casino", "brand": "LeoVegas", "aliases": ["leovegas", "leo vegas"]},
    {"domain": "williamhill.com", "category": "casino", "brand": "William Hill", "aliases": ["williamhill", "william hill"]},
    {"domain": "ladbrokes.com", "category": "casino", "brand": "Ladbrokes", "aliases": ["ladbrokes"]},
    {"domain": "coral.co.uk", "category": "casino", "brand": "Coral", "aliases": ["coral"]},
    {"domain": "marathonbet.com", "category": "casino", "brand": "Marathonbet", "aliases": ["marathonbet", "marathon bet"]},
    {"domain": "winline.ru", "category": "casino", "brand": "Winline", "aliases": ["winline"]},
    {"domain": "leon.ru", "category": "casino", "brand": "Leon", "aliases": ["leon"]},
    {"domain": "tennisi.kz", "category": "casino", "brand": "Tennisi", "aliases": ["tennisi"]},
    {"domain": "fairspin.io", "category": "casino", "brand": "Fairspin", "aliases": ["fairspin"]},
    {"domain": "zotabet.com", "category": "casino", "brand": "Zotabet", "aliases": ["zotabet"]},
    {"domain": "xparibet.com", "category": "casino", "brand": "XpariBet", "aliases": ["xparibet", "xpari"]},
    {"domain": "wazamba.com", "category": "casino", "brand": "Wazamba", "aliases": ["wazamba"]},
    {"domain": "nationalcasino.com", "category": "casino", "brand": "National Casino", "aliases": ["national casino"]},
]

BOOKMAKER_FIRST_BRANDS = {
    "1xbet",
    "1win",
    "22bet",
    "bet365",
    "betano",
    "betfair",
    "betway",
    "betwinner",
    "bwin",
    "cloudbet",
    "coral",
    "fonbet",
    "ggbet",
    "ladbrokes",
    "leon",
    "linebet",
    "marathonbet",
    "megapari",
    "melbet",
    "mostbet",
    "olimpbet",
    "parimatch",
    "rabona",
    "sportsbet",
    "stake",
    "tennisi",
    "unibet",
    "williamhill",
    "winline",
    "xparibet",
}

OFFICIAL_BOOKMAKER_DOMAINS = {
    "1xbet.com",
    "1xbet.kz",
    "1win.com",
    "22bet.com",
    "bet365.com",
    "betano.com",
    "betfair.com",
    "betway.com",
    "betwinner.com",
    "bwin.com",
    "coral.co.uk",
    "fonbet.kz",
    "fonbet.com",
    "ggbet.com",
    "ladbrokes.com",
    "leon.ru",
    "linebet.com",
    "marathonbet.com",
    "melbet.com",
    "mostbet.com",
    "olimpbet.kz",
    "olimpbet.com",
    "parimatch.kz",
    "parimatch.com",
    "tennisi.kz",
    "unibet.com",
    "williamhill.com",
    "winline.ru",
    "xparibet.com",
}

BOOKMAKER_FIRST_RE = re.compile(
    r"(?i)(?:^|[^a-z0-9])("
    + "|".join(re.escape(brand) for brand in sorted(BOOKMAKER_FIRST_BRANDS, key=len, reverse=True))
    + r")(?:[^a-z0-9]|$)"
)

CASINO_PRODUCT_SIGNAL_RE = re.compile(
    r"(?i)(casino|kazino|казино|slots?|слот|слоты|slot\s*games?|live\s+casino|roulette|рулет|"
    r"blackjack|блэкджек|poker|покер|jackpot|джекпот|free\s*spins?|фриспин|"
    r"игровые\s+автоматы|автоматы|1xslots|vulkan|joycasino|playfortuna|888casino|pinco|"
    r"pin[-_\s]?up|vavada|wazamba|leovegas|fairspin|zotabet|mrbit|casinia|ninecasino|playamo|"
    r"bitcasino|bitstarz|fortunejack|7bitcasino|casino[-_\s]?x|boomerang[-_\s]?casino|spinanga|"
    r"nomini|slottica|wildz|n1casino|rocketplay|hellspin|mystake|roobet|rollbit|bc\.?game|stake)"
)

BLOCKED_PAGE_SIGNAL_RE = re.compile(
    r"(?i)(access\s+(?:to\s+(?:this\s+)?site\s+is\s+)?blocked|access\s+denied|resource\s+is\s+blocked|"
    r"site\s+is\s+blocked|unavailable\s+for\s+legal\s+reasons|451\s+unavailable|blocked\s+by|"
    r"доступ.{0,80}(?:ограничен|запрещен|заблокирован)|сайт.{0,80}заблокирован|"
    r"ресурс.{0,80}заблокирован|заблокировано|по\s+решению\s+суда|"
    r"қолжетімділік.{0,80}шектелген|бұғатталған)"
)

MIRROR_TLDS = [
    "com",
    "net",
    "org",
    "site",
    "online",
    "club",
    "vip",
    "live",
    "pro",
    "xyz",
    "bet",
    "casino",
    "win",
    "io",
    "kz",
]

MIRROR_MODIFIERS = [
    "kz",
    "kaz",
    "top",
    "go",
    "login",
    "mirror",
    "zerkalo",
    "new",
    "club",
    "vip",
    "bonus",
    "play",
    "official",
    "app",
]

NON_TARGET_REGISTERED_DOMAINS = {
    "askgamblers.com",
    "banki.ru",
    "bcc.kz",
    "casino.guru",
    "bing.com",
    "duckduckgo.com",
    "finance.kz",
    "facebook.com",
    "forbes.kz",
    "github.com",
    "google.com",
    "informburo.kz",
    "instagram.com",
    "kapital.kz",
    "kursiv.media",
    "linkedin.com",
    "nur.kz",
    "ok.ru",
    "ranking.kz",
    "scamadviser.com",
    "sky.pro",
    "telegram.org",
    "t.me",
    "tengrinews.kz",
    "the-steppe.com",
    "trustpilot.com",
    "twitter.com",
    "vc.ru",
    "vk.com",
    "x.com",
    "youtube.com",
    "youtu.be",
    "ya.ru",
    "yandex.kz",
    "yandex.ru",
    "zakon.kz",
}

SEARCH_PAGE_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

USER_SEARCH_ENGINES = [
    {
        "name": "duckduckgo",
        "url": "https://html.duckduckgo.com/html/",
        "params": {"kl": "wt-wt"},
    },
    {
        "name": "google",
        "url": "https://www.google.com/search",
        "params": {"hl": "ru", "num": "20", "pws": "0", "gbv": "1"},
    },
    {
        "name": "bing",
        "url": "https://www.bing.com/search",
        "params": {"setlang": "ru-RU", "count": "20"},
    },
    {
        "name": "yandex_kz",
        "url": "https://yandex.kz/search/",
        "query_param": "text",
        "params": {"lr": "162", "lang": "ru"},
    },
]

SEARCH_MODES = {"auto", "casino", "phishing", "scam", "all"}

SEARCH_MODE_LABELS = {
    "auto": "авто",
    "casino": "казино",
    "phishing": "фишинг",
    "scam": "скам/легкие деньги",
    "all": "все категории",
}

CASINO_SEARCH_QUERIES = [
    "онлайн казино играть на деньги",
    "казино онлайн регистрация бонус",
    "слоты на деньги играть",
    "live casino roulette blackjack бонус",
    "казино зеркало рабочий вход",
    "онлайн казино без блокировки зеркало",
    "online casino slots bonus registration",
    "play online casino slots real money",
    "casino mirror login bonus slots",
    "vavada joycasino playfortuna vulkan casino зеркало",
]

SCAM_SEARCH_QUERIES = [
    "легкие деньги регистрация онлайн Казахстан",
    "быстрый заработок USDT регистрация Казахстан",
    "инвестиции быстрый доход личный кабинет Казахстан",
]

PHISHING_SEARCH_QUERIES = [
    "Kaspi фишинг вход Казахстан",
    "Kaspi получить деньги вход карта",
    "Kaspi подтвердить карту вход",
    "Halyk Bank фишинг вход Казахстан",
    "egov фишинг вход Казахстан",
]

USER_SEARCH_QUERIES = [*CASINO_SEARCH_QUERIES, *SCAM_SEARCH_QUERIES, *PHISHING_SEARCH_QUERIES]

DIRECT_USER_TARGET_RE = re.compile(
    r"(онлайн\s+казино|казино\s+(?:онлайн|играть|регистрац|вход|бонус|депозит)|"
    r"слот(?:ы|ов)?\s+на\s+деньг|играть\s+на\s+деньг|рабоч(?:ее|ий)\s+зеркал|"
    r"зеркал(?:о|а)?\s+(?:казино|вход)|официальн(?:ый|ое)\s+сайт|регистрац|"
    r"личн(?:ый|ого)\s+кабинет|депозит|пополнить|вывод\s+средств|бонус|промокод|"
    r"login|register|sign\s*up|deposit|withdraw|bonus|promo|play\s+now|casino|slots?|betting|bookmaker)",
    re.IGNORECASE,
)

STRONG_DIRECT_USER_TARGET_RE = re.compile(
    r"(регистрац|вход|личн(?:ый|ого)\s+кабинет|депозит|пополнить|вывод\s+средств|"
    r"бонус|промокод|играть\s+на\s+деньг|слот(?:ы|ов)?\s+на\s+деньг|"
    r"рабоч(?:ее|ий)\s+зеркал|login|register|sign\s*up|deposit|withdraw|bonus|promo|play\s+now)",
    re.IGNORECASE,
)

PHISHING_SEARCH_RE = re.compile(
    r"(phishing|фишинг|login|password|парол|kaspi|halyk|egov|карта|кошелек|wallet|verify|подтверд)",
    re.IGNORECASE,
)

SCAM_SEARCH_RE = re.compile(
    r"(легк(?:ие|их|ими)?\s+деньг|л[её]гк(?:ие|их|ими)?\s+деньг|"
    r"быстр(?:ый|ого|ые|ых)\s+(?:заработ|доход)|инвестиц|пассивн(?:ый|ого)\s+доход|"
    r"доход\s+без\s+влож|usdt|crypto|крипт|hyip|roi|гарантированн(?:ый|ая)\s+(?:доход|прибыл))",
    re.IGNORECASE,
)

BETTING_ONLY_RE = re.compile(
    r"(ставк(?:и|а)?\s+на\s+спорт|спортивн(?:ые|ая)\s+ставк|букмекер|букмекерск|"
    r"bookmaker|sportsbook|sports\s+betting|betting|коэффициент|линия\s+ставок|тотализатор)",
    re.IGNORECASE,
)

KZ_RELEVANCE_RE = re.compile(
    r"(казахстан|қазақстан|kazakhstan|kazakstan|\.kz\b|(?:^|[/.?=&_-])kz(?:$|[/.?=&_-]))",
    re.IGNORECASE,
)

INFORMATIONAL_SEARCH_URL_RE = re.compile(
    r"(?i)(?:^|[/.?=&_-])(?:news|novosti|journal|blog|wiki|article|articles|guide|guides|"
    r"learn|academy|media|press|story|stories|review|reviews|rating|ratings|obzor|otzyvy)"
    r"(?:$|[/.?=&_-])"
)

INFORMATIONAL_SEARCH_CONTEXT_RE = re.compile(
    r"(новост|журнал|стать[ьяи]|блог|вики|wiki|руководств|гайд|обзор|отзыв|рейтинг|"
    r"топ\s*\d|как\s+(?:заработ|играть|выбрать|получить)|способ(?:ов|ы)|"
    r"проверенн(?:ых|ые)\s+способ|что\s+такое|инструкц|совет|учеб|курс|банк|"
    r"инвестиции\s+в\s+казахстан|куда\s+инвестировать|финансов(?:ый|ые)\s+совет)",
    re.IGNORECASE,
)

INFORMATIONAL_DOMAIN_LABEL_RE = re.compile(
    r"(news|finance|bank|media|journal|academy|wiki|learn|kurs|edu|press|review|rating|guide|blog)",
    re.IGNORECASE,
)

CATEGORY_DISPLAY = {
    "legit": "обычный сайт",
    "casino": "казино или азартные игры",
    "online_casino": "онлайн-казино",
    "gambling": "казино или ставки",
    "betting": "букмекер/ставки",
    "sports_betting_review": "букмекер/ставки, требуется проверка лицензии",
    "phishing": "фишинг",
    "scam": "скам",
    "pyramid": "финансовая пирамида",
    "investment_pyramid": "финансовая пирамида",
    "empty_or_parked": "пустой или parking-сайт",
    "suspicious": "подозрительный сайт",
}

FEATURE_DISPLAY = {
    "url_length": "длина адреса",
    "hostname_length": "длина домена",
    "path_length": "длина пути страницы",
    "dot_count": "количество точек в адресе",
    "hyphen_count": "дефисы в адресе",
    "slash_count": "сложность пути",
    "digit_count": "цифры в адресе",
    "has_ip_host": "IP вместо домена",
    "has_at_symbol": "символ @ в адресе",
    "subdomain_count": "много уровней в домене",
    "suspicious_tld": "рискованная доменная зона",
    "domain_age_days": "возраст домена",
    "domain_expiry_days": "срок регистрации домена",
    "whois_privacy": "скрытый владелец домена",
    "registrar_country_kz": "регистратор в Казахстане",
    "whois_available": "наличие WHOIS/RDAP",
    "dns_a_count": "IP-адреса в DNS",
    "dns_mx_count": "почтовые MX-записи",
    "dns_txt_count": "TXT-записи DNS",
    "has_spf": "SPF для почты",
    "has_dmarc": "DMARC для почты",
    "ssl_valid": "SSL-сертификат",
    "ssl_days_to_expiry": "срок SSL-сертификата",
    "ssl_self_signed": "самоподписанный SSL",
    "ssl_issuer_known": "известный издатель SSL",
    "response_time_ms": "скорость ответа",
    "page_size_bytes": "размер страницы",
    "password_form_count": "форма ввода пароля",
    "iframe_count": "встроенные чужие блоки",
    "external_link_ratio": "доля внешних ссылок",
    "popup_or_redirect": "редиректы или всплывающие окна",
    "casino_keyword_count": "слова казино, ставок или бонусов",
    "pyramid_keyword_count": "обещания дохода или инвестиций",
    "phishing_keyword_count": "слова входа, пароля или кошелька",
    "casino_confidence_score": "уверенность по казино-маркерам",
    "casino_keywords_count": "слова казино, ставок или бонусов",
    "num_password_forms": "форма ввода пароля",
    "has_brand_impersonation": "упоминание чужого бренда",
    "num_suspicious_patterns": "подозрительный JavaScript",
    "has_casino_in_url": "казино или ставки в адресе",
    "num_external_links": "много внешних ссылок",
    "num_iframes": "встроенные чужие блоки",
    "has_meta_refresh": "автоматический редирект",
    "num_hidden_elements": "скрытые элементы страницы",
}


@dataclass
class Candidate:
    url: str
    domain: str
    category: str = "suspicious"
    why: str = ""
    search_query: str = ""
    source_urls: list[str] = field(default_factory=list)
    mirror_hints: list[str] = field(default_factory=list)
    brand: str | None = None

    def key(self) -> str:
        return registered_domain(self.domain or extract_domain(self.url))


class Investigator:
    def __init__(self, settings: Settings, db: Database, gemini: GeminiClient):
        self.settings = settings
        self.db = db
        self.gemini = gemini
        self.evidence = EvidenceCollector(settings)
        self.screenshots = ScreenshotService(settings)
        self.ml = DomainMLClassifier(settings)
        self.content_ai = ContentIntelligence(settings)
        self.cyberscan = CyberScanClassifier(settings)

    def run(
        self,
        run_id: int,
        seed_query: str | None,
        max_candidates: int,
        take_screenshots: bool,
        cancel_event: Event | None = None,
        search_mode: str = "auto",
    ) -> None:
        asyncio.run(self._run(run_id, seed_query, max_candidates, take_screenshots, cancel_event, search_mode))

    def run_manual(
        self,
        run_id: int,
        target: str,
        category: str,
        take_screenshots: bool,
        cancel_event: Event | None = None,
    ) -> None:
        asyncio.run(self._run_manual(run_id, target, category, take_screenshots, cancel_event))

    async def _run_manual(
        self,
        run_id: int,
        target: str,
        category: str,
        take_screenshots: bool,
        cancel_event: Event | None = None,
    ) -> None:
        self.db.update_run(run_id, status="running", candidate_count=1)
        if self.settings.require_kz_proxy and not self.settings.kz_proxy_url:
            message = "KZ proxy is required: set KZ_PROXY_URL, KZ_HTTP_PROXY, KZ_HTTPS_PROXY, or KZ_PROXY to a Kazakhstan HTTP/SOCKS proxy."
            self.db.update_run(run_id, status="failed", finished_at=utc_now(), error=message)
            self.db.add_log(run_id, "error", message, {"required": True, "configured": False})
            return
        self.db.add_log(run_id, "info", "Ручная проверка запущена", {"target": target, "started_at": utc_now()})
        methodology = [
            "Оператор вручную указал домен или URL для проверки.",
            "Gemini не используется, поэтому квота AI не тратится.",
            "Сайт открывается через ту же сеть проверки доступности, что и автоматический мониторинг.",
            "Для сайта собираются HTTP, HTML, SHA-256, DNS, TLS, RDAP, скорость ответа, редиректы и скриншот.",
        ]
        self.db.update_run(run_id, methodology_json=methodology)

        try:
            domain = extract_domain(target)
            if not is_candidate_domain(domain) or is_technical_url(target):
                message = "Укажите публичный домен или URL, а не IP, localhost или тестовый адрес."
                self.db.update_run(run_id, status="failed", finished_at=utc_now(), error=message)
                self.db.add_log(run_id, "error", "Ручная проверка остановлена", {"reason": message})
                return

            if cancel_event and cancel_event.is_set():
                self.db.update_run(run_id, status="canceled", finished_at=utc_now())
                self.db.add_log(run_id, "warning", "Ручная проверка остановлена до анализа сайта")
                return

            candidate = Candidate(
                url=normalize_url(target),
                domain=domain,
                category=self._category_from_domain_context(domain, target, (category or "manual").lower()),
                why="Домен указан оператором для ручной проверки.",
                search_query=target,
            )
            self.db.add_log(
                run_id,
                "info",
                "Открываю сайт для ручного анализа",
                {"domain": candidate.domain, "url": candidate.url},
            )
            finding = await self._build_finding(run_id, candidate, None, take_screenshots)
            if finding.get("_skip"):
                self.db.update_run(run_id, status="completed", finished_at=utc_now(), finding_count=0)
                self.db.add_log(
                    run_id,
                    "warning",
                    "Сайт не добавлен в отчет",
                    {
                        "domain": candidate.domain,
                        "reason": finding.get("_skip_reason", "не удалось открыть"),
                        "status_code": finding.get("status_code"),
                    },
                )
                return

            self.db.insert_finding(run_id, finding)
            self.db.update_run(run_id, status="completed", finished_at=utc_now(), finding_count=1)
            self.db.add_log(
                run_id,
                "info",
                "Ручная проверка завершена, сайт добавлен в отчет",
                {"domain": finding.get("domain"), "risk_score": finding.get("risk_score")},
            )
        except Exception as exc:  # noqa: BLE001
            self.db.update_run(run_id, status="failed", finished_at=utc_now(), error=f"{type(exc).__name__}: {exc}")
            self.db.add_log(run_id, "error", "Ручная проверка завершилась ошибкой", {"error": str(exc)})

    async def _run(
        self,
        run_id: int,
        seed_query: str | None,
        max_candidates: int,
        take_screenshots: bool,
        cancel_event: Event | None = None,
        search_mode: str = "auto",
    ) -> None:
        search_mode = self.normalize_search_mode(search_mode)
        self.db.update_run(run_id, status="running")
        self.db.add_log(
            run_id,
            "info",
            "Поиск запущен",
            {"started_at": utc_now(), "search_mode": search_mode, "search_mode_label": SEARCH_MODE_LABELS[search_mode]},
        )
        if self.settings.require_kz_proxy and not self.settings.kz_proxy_url:
            message = "KZ proxy is required: set KZ_PROXY_URL, KZ_HTTP_PROXY, KZ_HTTPS_PROXY, or KZ_PROXY to a Kazakhstan HTTP/SOCKS proxy."
            self.db.update_run(run_id, status="failed", finished_at=utc_now(), error=message)
            self.db.add_log(run_id, "error", message, {"required": True, "configured": False})
            return
        if self.settings.kz_proxy_url:
            self.db.add_log(
                run_id,
                "info",
                "Проверка доступности выполняется через казахстанскую точку",
                {"access_origin": self.settings.kz_access_label},
            )
        else:
            self.db.add_log(
                run_id,
                "info",
                "KZ_PROXY_URL не настроен: проверка доступности идет из сети хостинга",
                {"access_origin": self.settings.kz_access_label},
            )

        methodology = [
            f"Режим поиска: {SEARCH_MODE_LABELS[search_mode]}.",
            "Ищем подозрительные casino/scam сайты через поисковую выдачу DuckDuckGo/Google/Bing; Gemini используется только как опциональный fallback.",
            "В поисковых запросах берем живые домены, рабочие зеркала и страницы, доступные для пользователей Казахстана.",
            "Открытие кандидатов проверяем через KZ_PROXY_URL; если прокси не задан, фиксируем прямую сеть сервера как ограничение доказательства.",
            "Отбрасываем IP-адреса, localhost, тестовые домены и технические источники.",
            "Оставляем в таблице только сайты, которые удалось открыть и зафиксировать, а страницы блокировки не показываем как рабочие сайты.",
            "Для каждого открытого сайта сохраняем HTML, SHA-256, DNS/TLS, RDAP, скорость ответа, размер страницы, редиректы и скриншот.",
            "Зеркала ищем отдельно по найденным доменам и похожести имен.",
            "Все ошибки и пропущенные сайты пишем в журнал проверки и терминал.",
        ]
        self.db.update_run(run_id, methodology_json=methodology)

        try:
            findings_count = self.db.count_findings(run_id)
            attempted_domains: set[str] = set()
            discovery_round = 0
            checked_total = 0
            no_candidate_rounds = 0

            def handle_inspection_result(finding: dict[str, Any]) -> None:
                nonlocal findings_count
                if finding.get("_skip"):
                    self.db.add_log(
                        run_id,
                        "warning",
                        "Сайт пропущен и не показан пользователю",
                        {
                            "index": finding.get("_candidate_index"),
                            "total": finding.get("_candidate_total"),
                            "domain": finding.get("domain"),
                            "reason": finding.get("_skip_reason", "не удалось открыть"),
                            "status_code": finding.get("status_code"),
                        },
                    )
                    return

                self.db.insert_finding(run_id, finding)
                findings_count += 1
                self.db.update_run(run_id, finding_count=findings_count)
                self.db.add_log(
                    run_id,
                    "info",
                    "Сайт добавлен в отчет",
                    {
                        "domain": finding.get("domain"),
                        "risk_score": finding.get("risk_score"),
                        "findings": findings_count,
                        "target": max_candidates,
                    },
                )

            while findings_count < max_candidates:
                if cancel_event and cancel_event.is_set():
                    self.db.update_run(run_id, status="canceled", finished_at=utc_now(), finding_count=findings_count)
                    self.db.add_log(run_id, "warning", "Проверка остановлена пользователем", {"findings": findings_count})
                    return

                discovery_round += 1
                remaining = max(1, max_candidates - findings_count)
                candidates = await self._discover_candidates(
                    run_id,
                    seed_query,
                    max_candidates,
                    search_mode,
                    excluded_domains=attempted_domains,
                )
                fresh_candidates = [
                    candidate
                    for candidate in candidates
                    if candidate.key() and candidate.key() not in attempted_domains
                ]
                candidate_check_limit = self._candidate_check_limit(remaining, len(fresh_candidates), search_mode)
                candidates_to_check = fresh_candidates[:candidate_check_limit]
                checked_total += len(candidates_to_check)
                self.db.update_run(run_id, candidate_count=checked_total)
                self.db.add_log(
                    run_id,
                    "info",
                    "Список сайтов-кандидатов готов",
                    {
                        "round": discovery_round,
                        "count": len(candidates),
                        "checking": len(candidates_to_check),
                        "checked_total": checked_total,
                        "target_findings": max_candidates,
                        "already_saved": findings_count,
                    },
                )

                if not candidates_to_check:
                    no_candidate_rounds += 1
                    self.db.add_log(
                        run_id,
                        "warning",
                        "Новых кандидатов для проверки не осталось",
                        {
                            "round": discovery_round,
                            "findings": findings_count,
                            "target": max_candidates,
                            "attempted": len(attempted_domains),
                        },
                    )
                    if no_candidate_rounds >= 2 or len(attempted_domains) >= self.settings.max_candidates_per_run:
                        break
                    continue
                no_candidate_rounds = 0

                mirror_groups = await self._discover_mirrors(run_id, candidates_to_check, search_mode)
                concurrency = max(1, min(self.settings.scan_concurrency, remaining, len(candidates_to_check) or 1))
                self.db.add_log(
                    run_id,
                    "info",
                    "Пакетная проверка кандидатов запущена",
                    {
                        "round": discovery_round,
                        "target": max_candidates,
                        "target_findings": max_candidates,
                        "candidates": len(candidates_to_check),
                        "concurrency": concurrency,
                        "already_saved": findings_count,
                    },
                )
                semaphore = asyncio.Semaphore(concurrency)

                if concurrency <= 1:
                    for index, candidate in enumerate(candidates_to_check, start=1):
                        if cancel_event and cancel_event.is_set():
                            self.db.update_run(run_id, status="canceled", finished_at=utc_now(), finding_count=findings_count)
                            self.db.add_log(run_id, "warning", "Проверка остановлена пользователем", {"findings": findings_count})
                            return
                        if findings_count >= max_candidates:
                            break
                        key = candidate.key()
                        if key:
                            attempted_domains.add(key)
                        finding = await self._inspect_candidate(
                            run_id,
                            index,
                            len(candidates_to_check),
                            candidate,
                            candidates_to_check,
                            mirror_groups,
                            take_screenshots,
                            semaphore,
                            cancel_event,
                            search_mode,
                        )
                        handle_inspection_result(finding)
                else:
                    for candidate in candidates_to_check:
                        key = candidate.key()
                        if key:
                            attempted_domains.add(key)
                    tasks = [
                        asyncio.create_task(
                            self._inspect_candidate(
                                run_id,
                                index,
                                len(candidates_to_check),
                                candidate,
                                candidates_to_check,
                                mirror_groups,
                                take_screenshots,
                                semaphore,
                                cancel_event,
                                search_mode,
                            )
                        )
                        for index, candidate in enumerate(candidates_to_check, start=1)
                    ]

                    try:
                        for task in asyncio.as_completed(tasks):
                            if cancel_event and cancel_event.is_set():
                                self.db.update_run(run_id, status="canceled", finished_at=utc_now(), finding_count=findings_count)
                                self.db.add_log(run_id, "warning", "Проверка остановлена пользователем", {"findings": findings_count})
                                return
                            if findings_count >= max_candidates:
                                break

                            finding = await task
                            handle_inspection_result(finding)
                    finally:
                        for task in tasks:
                            if not task.done():
                                task.cancel()
                        if tasks:
                            await asyncio.gather(*tasks, return_exceptions=True)

                if findings_count < max_candidates and len(attempted_domains) >= self.settings.max_candidates_per_run:
                    self.db.add_log(
                        run_id,
                        "warning",
                        "Достигнут технический лимит проверенных доменов до набора цели",
                        {
                            "findings": findings_count,
                            "target": max_candidates,
                            "attempted": len(attempted_domains),
                            "limit": self.settings.max_candidates_per_run,
                        },
                    )
                    break

            self.db.update_run(run_id, status="completed", finished_at=utc_now(), finding_count=findings_count)
            if findings_count >= max_candidates:
                self.db.add_log(run_id, "info", "Поиск завершен: выбранная цель набрана", {"findings": findings_count, "target": max_candidates})
            else:
                self.db.add_log(
                    run_id,
                    "warning",
                    "Поиск завершен ниже выбранной цели: открытых подходящих сайтов оказалось меньше цели",
                    {"findings": findings_count, "target": max_candidates, "attempted": len(attempted_domains)},
                )
        except Exception as exc:  # noqa: BLE001
            self.db.update_run(run_id, status="failed", finished_at=utc_now(), error=f"{type(exc).__name__}: {exc}")
            self.db.add_log(run_id, "error", "Поиск завершился ошибкой", {"error": str(exc)})

    def _candidate_check_limit(self, target_findings: int, available_candidates: int, search_mode: str) -> int:
        if available_candidates <= 0:
            return 0
        target_findings = max(1, int(target_findings))
        multiplier = 50 if self.normalize_search_mode(search_mode) == "casino" else 2
        desired = max(target_findings, target_findings * multiplier)
        return min(available_candidates, self.settings.max_candidates_per_run, desired)

    async def _inspect_candidate(
        self,
        run_id: int,
        index: int,
        total: int,
        candidate: Candidate,
        all_candidates: list[Candidate],
        mirror_groups: list[dict[str, Any]],
        take_screenshots: bool,
        semaphore: asyncio.Semaphore,
        cancel_event: Event | None = None,
        search_mode: str = "auto",
    ) -> dict[str, Any]:
        async with semaphore:
            if cancel_event and cancel_event.is_set():
                return {
                    "_skip": True,
                    "_skip_reason": "проверка остановлена пользователем",
                    "_candidate_index": index,
                    "_candidate_total": total,
                    "url": candidate.url,
                    "domain": candidate.domain,
                }

            self.db.add_log(
                run_id,
                "info",
                "Открываю сайт-кандидат",
                {"index": index, "total": total, "domain": candidate.domain, "url": candidate.url},
            )
            mirror_group = self._mirror_group_for(candidate, all_candidates, mirror_groups)
            try:
                finding = await asyncio.wait_for(
                    self._build_finding(run_id, candidate, mirror_group, take_screenshots, search_mode),
                    timeout=self.settings.candidate_timeout_seconds,
                )
            except asyncio.TimeoutError:
                return {
                    "_skip": True,
                    "_skip_reason": f"таймаут проверки сайта {self.settings.candidate_timeout_seconds} сек.",
                    "_candidate_index": index,
                    "_candidate_total": total,
                    "url": candidate.url,
                    "domain": candidate.domain,
                }
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                return {
                    "_skip": True,
                    "_skip_reason": f"{type(exc).__name__}: {exc}",
                    "_candidate_index": index,
                    "_candidate_total": total,
                    "url": candidate.url,
                    "domain": candidate.domain,
                }

            finding.setdefault("_candidate_index", index)
            finding.setdefault("_candidate_total", total)
            finding.setdefault("domain", candidate.domain)
            finding.setdefault("url", candidate.url)
            return finding

    async def _discover_candidates(
        self,
        run_id: int,
        seed_query: str | None,
        max_candidates: int,
        search_mode: str = "auto",
        excluded_domains: set[str] | None = None,
    ) -> list[Candidate]:
        search_mode = self._effective_search_mode(seed_query, search_mode)
        excluded_domains = {
            registered_domain(domain)
            for domain in (excluded_domains or set())
            if registered_domain(domain)
        }
        discovery_limit = min(
            max(max_candidates * 60, 5000),
            max(max_candidates, self.settings.osint_candidate_pool_size),
        )
        candidate_target = max_candidates
        if search_mode == "casino" and max_candidates >= 100:
            candidate_target = min(
                discovery_limit,
                self.settings.max_candidates_per_run,
                max_candidates * 50,
            )
        discovered: list[Candidate] = []
        user_search_mode = self._user_search_mode(seed_query, search_mode)

        if user_search_mode:
            try:
                discovered.extend(self._discover_with_user_search(run_id, seed_query, discovery_limit, max_candidates, search_mode))
            except GeminiAPIError as exc:
                level = "warning" if exc.status_code in {401, 403} else "error"
                self.db.add_log(
                    run_id,
                    level,
                    "Gemini Search недоступен для пользовательского поиска",
                    {"error": str(exc), "status_code": exc.status_code},
                )
            except Exception as exc:  # noqa: BLE001
                self.db.add_log(run_id, "warning", "Пользовательский поиск недоступен", {"error": str(exc)})
            if self.settings.osint_feeds_enabled and len(discovered) < candidate_target:
                feed_candidates = await self._discover_from_feeds(run_id, discovery_limit)
                matched_feeds = [
                    candidate
                    for candidate in feed_candidates
                    if self._candidate_matches_user_search(candidate, seed_query or "онлайн казино", search_mode)
                ]
                if matched_feeds:
                    discovered.extend(matched_feeds)
                    self.db.add_log(
                        run_id,
                        "warning",
                        "OSINT fallback добавил кандидатов после недоступного поискового поиска",
                        {"added": len(matched_feeds), "reason": "Search pages unavailable or returned too few casino domains"},
                    )
        else:
            if self.settings.osint_feeds_enabled:
                feed_candidates = await self._discover_from_feeds(run_id, discovery_limit)
                discovered.extend(feed_candidates)

            if self.gemini.available:
                try:
                    gemini_limit = min(discovery_limit, max(max_candidates * 2, 50))
                    discovered.extend(self._discover_with_gemini(run_id, seed_query, gemini_limit, search_mode))
                except GeminiAPIError as exc:
                    level = "warning" if exc.status_code in {401, 403} else "error"
                    self.db.add_log(
                        run_id,
                        level,
                        "Gemini Search недоступен, продолжаю через OSINT/ML",
                        {"error": str(exc), "status_code": exc.status_code},
                    )
                    if not discovered and not self.settings.osint_feeds_enabled:
                        discovered.extend(await self._discover_from_feeds(run_id, discovery_limit))
                except Exception as exc:  # noqa: BLE001
                    self.db.add_log(run_id, "warning", "Gemini Search недоступен, продолжаю через OSINT/ML", {"error": str(exc)})
                    if not discovered and not self.settings.osint_feeds_enabled:
                        discovered.extend(await self._discover_from_feeds(run_id, discovery_limit))
            else:
                self.db.add_log(run_id, "warning", "Gemini ключ не настроен. Автопоиск продолжается через OSINT-фиды.")

        if seed_query:
            for domain in find_domains(seed_query):
                if not is_candidate_domain(domain):
                    continue
                discovered.append(
                    Candidate(
                        url=normalize_url(domain),
                        domain=domain,
                        category=self._category_from_domain_context(domain, seed_query, "manual"),
                        why="Домен указан оператором вручную.",
                        search_query=seed_query,
                    )
                )

        seed_domains = set(find_domains(seed_query or ""))
        allow_synthetic_refill = (
            not user_search_mode
            or (search_mode == "casino" and not seed_domains and len(discovered) < candidate_target)
        )

        if allow_synthetic_refill and len(discovered) < candidate_target:
            bootstrap = self._discover_from_bootstrap(seed_query, candidate_target - len(discovered), search_mode)
            if bootstrap:
                discovered.extend(bootstrap)
                self.db.add_log(
                    run_id,
                    "warning",
                    "Discovery bootstrap добавил кандидатов для проверки",
                    {"added": len(bootstrap), "reason": "Gemini/OSINT дали мало доменов"},
                )

        candidates = self._sort_candidates_for_search_mode(
            self._dedupe_candidates(discovered, discovery_limit),
            search_mode,
        )
        known_domains = self.db.known_domains()
        fresh_after_known, skipped_known = self._exclude_known_candidates(candidates, known_domains)
        fresh_candidates, skipped_attempted = self._exclude_known_candidates(fresh_after_known, excluded_domains)
        known_rechecked = 0
        algorithmic_added = 0

        if allow_synthetic_refill and len(fresh_candidates) < candidate_target and not seed_domains:
            algorithmic_excluded = known_domains | excluded_domains | {candidate.key() for candidate in candidates}
            algorithmic = self._discover_from_algorithmic_mirrors(
                seed_query,
                candidate_target - len(fresh_candidates),
                algorithmic_excluded,
                search_mode,
            )
            if algorithmic:
                fresh_candidates.extend(algorithmic)
                algorithmic_added = len(algorithmic)
                self.db.add_log(
                    run_id,
                    "warning",
                    "Algorithmic discovery добавил кандидатов для расширенного прохода",
                    {
                        "added": algorithmic_added,
                        "reason": "Gemini/OSINT дали мало новых доменов",
                    },
                )

        if allow_synthetic_refill and len(fresh_candidates) < candidate_target and not seed_domains:
            refill_count = candidate_target - len(fresh_candidates)
            known_candidates = [
                candidate
                for candidate in candidates
                if candidate.key() in known_domains and candidate.key() not in excluded_domains
            ][:refill_count]
            if known_candidates:
                fresh_candidates.extend(known_candidates)
                known_rechecked = len(known_candidates)
        self.db.add_log(
            run_id,
            "info",
            "Discovery candidates deduplicated",
            {
                "raw": len(discovered),
                "deduped": len(candidates),
                "skipped_known": skipped_known,
                "skipped_attempted": skipped_attempted,
                "algorithmic_added": algorithmic_added,
                "known_rechecked": known_rechecked,
                "ready": len(fresh_candidates),
            },
        )
        return self._sort_candidates_for_search_mode(fresh_candidates, search_mode)[:discovery_limit]

    def _discover_with_user_search(
        self,
        run_id: int,
        seed_query: str | None,
        discovery_limit: int,
        max_candidates: int,
        search_mode: str = "auto",
    ) -> list[Candidate]:
        search_mode = self._effective_search_mode(seed_query, search_mode)
        queries = self._user_search_queries(seed_query, search_mode)
        per_query_limit = max(12, min(40, max_candidates))
        candidates: list[Candidate] = []
        seen: set[str] = set()
        search_issues: list[dict[str, Any]] = []
        self.db.add_log(
            run_id,
            "info",
            "User-search discovery started",
            {
                "queries": queries,
                "mode": "search-page-user-results",
                "search_mode": search_mode,
                "search_pages_enabled": self.settings.search_pages_enabled,
                "gemini_fallback": self.settings.gemini_user_search_fallback,
            },
        )
        for query in queries:
            if len(candidates) >= discovery_limit:
                break
            batch: list[Candidate] = []
            if self.settings.search_pages_enabled:
                batch.extend(
                    self._discover_from_search_pages(
                        run_id,
                        query,
                        per_query_limit,
                        search_mode,
                        search_issues,
                    )
                )
            if len(batch) < max(3, min(per_query_limit, max_candidates)) and self.settings.gemini_user_search_fallback:
                self.db.add_log(
                    run_id,
                    "info",
                    "Gemini fallback enabled for user-search query",
                    {"query": query, "search_page_candidates": len(batch)},
                )
                try:
                    batch.extend(self._discover_with_gemini(run_id, query, per_query_limit, search_mode))
                except GeminiQuotaError:
                    raise
                except GeminiAPIError:
                    raise
            for candidate in batch:
                key = candidate.key()
                if not key or key in seen:
                    continue
                if not self._candidate_matches_user_search(candidate, query, search_mode):
                    continue
                seen.add(key)
                if not candidate.search_query:
                    candidate.search_query = query
                candidates.append(candidate)
                if len(candidates) >= discovery_limit:
                    break
        self._log_search_page_issues(run_id, search_issues, len(queries), len(candidates))
        self.db.add_log(
            run_id,
            "info",
            "User-search discovery finished",
            {"queries": len(queries), "candidates": len(candidates)},
        )
        return self._sort_candidates_for_search_mode(candidates, search_mode)

    def _discover_from_search_pages(
        self,
        run_id: int,
        query: str,
        limit: int,
        search_mode: str = "auto",
        search_issues: list[dict[str, Any]] | None = None,
    ) -> list[Candidate]:
        if limit <= 0:
            return []
        timeout = min(max(self.settings.request_timeout_seconds, 8), 14)
        headers = {
            "User-Agent": SEARCH_PAGE_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "ru-KZ,ru;q=0.9,en;q=0.6",
        }
        candidates: list[Candidate] = []
        seen: set[str] = set()
        search_issues = search_issues if search_issues is not None else []
        with httpx.Client(
            timeout=timeout,
            headers=headers,
            follow_redirects=True,
            proxy=self.settings.kz_proxy_url,
        ) as client:
            request_count = 0
            for engine in USER_SEARCH_ENGINES:
                engine_name = str(engine["name"])
                if len(candidates) >= limit:
                    break
                url = self._search_engine_url(engine, query)
                try:
                    if request_count and self.settings.search_page_delay_seconds > 0:
                        time.sleep(self.settings.search_page_delay_seconds)
                    request_count += 1
                    response = client.get(url)
                    response.raise_for_status()
                except Exception as exc:  # noqa: BLE001
                    error, status_code = self._search_error_summary(exc)
                    issue: dict[str, Any] = {"engine": engine_name, "query": query, "error": error}
                    if status_code is not None:
                        issue["status_code"] = status_code
                    search_issues.append(issue)
                    continue
                parsed = self._candidates_from_search_html(
                    query=query,
                    html=response.text,
                    source_url=str(response.url),
                    engine=engine_name,
                    limit=limit - len(candidates),
                    search_mode=search_mode,
                )
                added = 0
                for candidate in parsed:
                    key = candidate.key()
                    if not key or key in seen:
                        continue
                    seen.add(key)
                    candidates.append(candidate)
                    added += 1
                    if len(candidates) >= limit:
                        break
                if added:
                    self.db.add_log(
                        run_id,
                        "info",
                        "Search page processed",
                        {"engine": engine_name, "query": query, "added": added},
                    )
        return candidates

    @staticmethod
    def _search_engine_url(engine: dict[str, Any], query: str) -> str:
        query_param = str(engine.get("query_param") or "q")
        params = {**dict(engine.get("params") or {}), query_param: query}
        return f"{engine['url']}?{urlencode(params)}"

    def _log_search_page_issues(self, run_id: int, issues: list[dict[str, Any]], queries: int, candidates: int) -> None:
        if not issues:
            return
        summary: dict[tuple[str, str, int | None], int] = {}
        for issue in issues:
            key = (
                str(issue.get("engine") or "unknown"),
                str(issue.get("error") or "error"),
                issue.get("status_code") if isinstance(issue.get("status_code"), int) else None,
            )
            summary[key] = summary.get(key, 0) + 1
        failures = [
            {
                "engine": engine,
                "error": error,
                "count": count,
                **({"status_code": status_code} if status_code is not None else {}),
            }
            for (engine, error, status_code), count in sorted(summary.items(), key=lambda item: (-item[1], item[0][0]))
        ]
        self.db.add_log(
            run_id,
            "warning" if candidates == 0 else "info",
            "Search pages degraded" if candidates else "Search pages unavailable",
            {"queries": queries, "candidates": candidates, "failures": failures[:5]},
        )

    @staticmethod
    def _search_error_summary(exc: Exception) -> tuple[str, int | None]:
        if isinstance(exc, httpx.HTTPStatusError):
            response = exc.response
            status_code = response.status_code
            if status_code == 429:
                return "HTTP 429 Too Many Requests", status_code
            reason = response.reason_phrase or "HTTP error"
            return f"HTTP {status_code} {reason}", status_code
        if isinstance(exc, httpx.TimeoutException):
            return "timed out", None
        if isinstance(exc, httpx.RequestError):
            return exc.__class__.__name__, None
        return exc.__class__.__name__, None

    def _candidates_from_search_html(
        self,
        *,
        query: str,
        html: str,
        source_url: str,
        engine: str,
        limit: int,
        search_mode: str = "auto",
    ) -> list[Candidate]:
        search_mode = self._effective_search_mode(query, search_mode)
        candidates: list[Candidate] = []
        soup = BeautifulSoup(html or "", "html.parser")
        for anchor in soup.find_all("a", href=True):
            if len(candidates) >= limit:
                break
            href = str(anchor.get("href") or "").strip()
            if not href or href.startswith(("#", "javascript:", "mailto:")):
                continue
            target_url = unwrap_known_redirect_url(urljoin(source_url, href))
            title = re.sub(r"\s+", " ", anchor.get_text(" ", strip=True))
            parent = anchor.find_parent(["article", "li", "div"])
            snippet = re.sub(r"\s+", " ", parent.get_text(" ", strip=True)) if parent else title
            if not title and not target_url:
                continue
            source_context = f"{title} {snippet} {target_url}"
            query_context = f"{query} {source_context}"
            if self._is_informational_search_result(target_url, query_context, search_mode):
                continue
            category = self._category_from_search_result(source_context)
            if (
                search_mode == "casino"
                and category == "suspicious"
                and self._looks_like_kz_search_landing(extract_domain(target_url))
                and has_casino_context(query)
            ):
                category = "casino"
            domain_signals = gambling_domain_signals(target_url, query_context if search_mode == "casino" else source_context)
            if category == "suspicious" and not domain_signals:
                continue
            candidate = self._candidate_from_item(
                {
                    "url": target_url,
                    "title": title,
                    "snippet": snippet,
                    "category": category,
                    "why": f"Домен найден в поисковой выдаче {engine} по пользовательскому запросу.",
                    "search_query": query,
                    "source_urls": [source_url],
                },
                default_sources=[],
            )
            if not candidate or not self._candidate_matches_user_search(candidate, query, search_mode):
                continue
            candidates.append(candidate)
        return self._sort_candidates_for_search_mode(self._dedupe_candidates(candidates, limit), search_mode)

    def _is_informational_search_result(self, url: str, context: str, search_mode: str = "auto") -> bool:
        domain = extract_domain(url)
        if self._is_non_target_source_domain(domain):
            return True
        search_mode = self.normalize_search_mode(search_mode)
        direct_target = self._has_direct_user_target_signal(url, context)
        strong_direct_target = self._has_strong_direct_user_target_signal(url, context)
        stem = registered_domain(domain).split(".", 1)[0]
        if INFORMATIONAL_DOMAIN_LABEL_RE.search(stem) and not strong_direct_target:
            return True
        if gambling_domain_signals(domain, context):
            return False
        text = f"{url} {context}"
        if INFORMATIONAL_SEARCH_URL_RE.search(url or "") or INFORMATIONAL_SEARCH_CONTEXT_RE.search(text):
            return not strong_direct_target
        if search_mode == "casino":
            return not direct_target
        return False

    @staticmethod
    def _has_direct_user_target_signal(url: str, context: str) -> bool:
        text = f"{url} {context}"
        return bool(DIRECT_USER_TARGET_RE.search(text) or gambling_domain_signals(extract_domain(url), text))

    @staticmethod
    def _has_strong_direct_user_target_signal(url: str, context: str) -> bool:
        return bool(STRONG_DIRECT_USER_TARGET_RE.search(f"{url} {context}"))

    @staticmethod
    def _category_from_search_result(text: str) -> str:
        if has_casino_context(text):
            return "casino"
        if has_user_risk_search_context(text):
            return "scam"
        return "suspicious"

    @staticmethod
    def normalize_search_mode(search_mode: str | None) -> str:
        normalized = re.sub(r"[^a-z_]+", "", (search_mode or "auto").strip().lower())
        return normalized if normalized in SEARCH_MODES else "auto"

    @staticmethod
    def _effective_search_mode(seed_query: str | None, search_mode: str | None = "auto") -> str:
        normalized = Investigator.normalize_search_mode(search_mode)
        if normalized != "auto":
            return normalized
        text = seed_query or ""
        if PHISHING_SEARCH_RE.search(text):
            return "phishing"
        if SCAM_SEARCH_RE.search(text) and not has_casino_context(text):
            return "scam"
        if has_casino_context(text):
            return "casino"
        return "auto"

    @staticmethod
    def _user_search_mode(seed_query: str | None, search_mode: str | None = "auto") -> bool:
        effective_mode = Investigator._effective_search_mode(seed_query, search_mode)
        return effective_mode in {"casino", "phishing", "scam", "all"} or has_user_risk_search_context(seed_query or "")

    @staticmethod
    def _user_search_queries(seed_query: str | None, search_mode: str | None = "auto") -> list[str]:
        effective_mode = Investigator._effective_search_mode(seed_query, search_mode)
        queries: list[str] = []
        if seed_query and seed_query.strip():
            queries.append(seed_query.strip())
        if effective_mode == "casino":
            queries.extend(CASINO_SEARCH_QUERIES)
        elif effective_mode == "phishing":
            queries.extend(PHISHING_SEARCH_QUERIES)
        elif effective_mode == "scam":
            queries.extend(SCAM_SEARCH_QUERIES)
        elif effective_mode == "all" or not seed_query or has_user_risk_search_context(seed_query):
            queries.extend(USER_SEARCH_QUERIES)
        clean: list[str] = []
        for query in queries:
            normalized = re.sub(r"\s+", " ", query).strip()
            if normalized and normalized not in clean:
                clean.append(normalized)
        if effective_mode == "casino":
            return clean[:10]
        if effective_mode in {"phishing", "scam"}:
            return clean[:8]
        return clean[:10]

    @staticmethod
    def _looks_like_kz_search_landing(domain: str) -> bool:
        domain = extract_domain(domain)
        if not domain or not registered_domain(domain).endswith(".kz"):
            return False
        labels = [re.sub(r"[^a-z0-9]+", "", label.lower()) for label in domain.split(".") if label]
        registered_labels = registered_domain(domain).split(".")
        sub_labels = labels[: max(0, len(labels) - len(registered_labels))]
        return any(label in {"top", "go", "play", "app", "start", "lk", "m", "win", "vip", "club", "bonus", "online"} for label in sub_labels) or any(
            re.fullmatch(r"[a-z]{2,12}\d{1,4}", label) for label in sub_labels
        )

    @staticmethod
    def _casino_kz_relevance_score(url: str, context: str) -> int:
        domain = extract_domain(url)
        registered = registered_domain(domain)
        text = f"{url} {context}"
        score = 0
        if registered.endswith(".kz"):
            score += 120
        if Investigator._looks_like_kz_search_landing(domain):
            score += 60
        if KZ_RELEVANCE_RE.search(text):
            score += 60
        return score

    @staticmethod
    def _has_casino_product_signal(text: str | None) -> bool:
        return bool(CASINO_PRODUCT_SIGNAL_RE.search(text or ""))

    @staticmethod
    def _is_bookmaker_first_context(text: str | None) -> bool:
        return bool(BOOKMAKER_FIRST_RE.search(text or ""))

    @staticmethod
    def _is_official_bookmaker_domain(domain_or_url: str | None) -> bool:
        domain = extract_domain(str(domain_or_url or ""))
        registered = registered_domain(domain)
        return bool(registered and registered in OFFICIAL_BOOKMAKER_DOMAINS)

    @staticmethod
    def _looks_like_blocked_page(content_ai: dict[str, Any], evidence: Any) -> bool:
        quality = content_ai.get("site_quality") or {}
        text = " ".join(
            [
                str(getattr(evidence, "title", "") or ""),
                str(getattr(evidence, "description", "") or ""),
                str(getattr(evidence, "text_excerpt", "") or ""),
                " ".join(str(marker) for marker in quality.get("markers") or []),
                " ".join(str(signal) for signal in content_ai.get("signals") or []),
            ]
        )
        return bool(BLOCKED_PAGE_SIGNAL_RE.search(text))

    @staticmethod
    def _bootstrap_item_category(item: dict[str, Any]) -> str:
        raw_values = [
            str(item.get("brand") or ""),
            extract_domain(str(item.get("domain") or "")).split(".", 1)[0],
            *[str(alias) for alias in item.get("aliases", [])],
        ]
        for value in raw_values:
            clean = re.sub(r"[^a-z0-9]+", "", value.lower())
            if clean in BOOKMAKER_FIRST_BRANDS:
                return "betting"
        return str(item.get("category") or "suspicious")

    def _sort_candidates_for_search_mode(self, candidates: list[Candidate], search_mode: str | None) -> list[Candidate]:
        effective_mode = self.normalize_search_mode(search_mode)
        if effective_mode == "auto":
            return candidates
        return sorted(
            candidates,
            key=lambda candidate: (
                -self._candidate_search_rank(candidate, effective_mode),
                candidate.key(),
            ),
        )

    @staticmethod
    def _candidate_search_rank(candidate: Candidate, search_mode: str) -> int:
        context = " ".join([candidate.domain, candidate.url, candidate.category, candidate.why])
        product_context = " ".join([candidate.domain, candidate.url, candidate.why])
        category_tokens = set(re.split(r"[^a-z_]+", candidate.category.lower()))
        if search_mode == "casino":
            score = 0
            has_casino_product = Investigator._has_casino_product_signal(product_context)
            bookmaker_first = Investigator._is_bookmaker_first_context(product_context)
            score += max(0, Investigator._casino_kz_relevance_score(candidate.url, context))
            if Investigator._is_official_bookmaker_domain(candidate.domain):
                score -= 500
            if bookmaker_first:
                score -= 500
            if category_tokens & {"casino", "online_casino"}:
                score += 120
            if has_casino_product:
                score += 90
            if re.search(r"(?i)(/casino|casino|slots?|slot|roulette|blackjack|jackpot|vulkan|joycasino|pinco|pin[-_]?up)", candidate.url):
                score += 70
            if Investigator._looks_like_kz_search_landing(candidate.domain):
                score += 45
            if category_tokens & {"betting", "gambling"} and not has_casino_product:
                score -= 80
            if bookmaker_first and not has_casino_product:
                score -= 160
            if BETTING_ONLY_RE.search(context) and not has_casino_product:
                score -= 60
            if category_tokens & {"phishing", "scam", "pyramid", "investment_pyramid"}:
                score -= 100
            return score
        if search_mode == "phishing":
            return (120 if "phishing" in category_tokens else 0) + (60 if PHISHING_SEARCH_RE.search(context) else 0)
        if search_mode == "scam":
            return (120 if category_tokens & {"scam", "pyramid", "investment_pyramid"} else 0) + (60 if SCAM_SEARCH_RE.search(context) else 0)
        return 0

    @staticmethod
    def _candidate_matches_user_search(candidate: Candidate, query: str, search_mode: str | None = "auto") -> bool:
        effective_mode = Investigator._effective_search_mode(query, search_mode)
        candidate_context = " ".join(
            [
                candidate.domain,
                candidate.url,
                candidate.category,
                candidate.why,
            ]
        )
        category_tokens = set(re.split(r"[^a-z_]+", candidate.category.lower()))
        if effective_mode == "casino":
            if Investigator._is_official_bookmaker_domain(candidate.domain) or Investigator._is_official_bookmaker_domain(candidate.url):
                return False
            product_context = " ".join([candidate.domain, candidate.url, candidate.why])
            has_casino_product = Investigator._has_casino_product_signal(product_context)
            bookmaker_first = Investigator._is_bookmaker_first_context(product_context)
            if bookmaker_first:
                return False
            if category_tokens & {"casino", "online_casino"}:
                return not bookmaker_first or has_casino_product
            if has_casino_product:
                return True
            if Investigator._looks_like_kz_search_landing(candidate.domain) and has_casino_context(query):
                return True
            return False
        if effective_mode == "phishing":
            return bool(category_tokens & {"phishing"} or PHISHING_SEARCH_RE.search(candidate_context))
        if effective_mode == "scam":
            return bool(
                category_tokens & {"scam", "pyramid", "investment_pyramid"}
                or (SCAM_SEARCH_RE.search(candidate_context) and not has_casino_context(candidate_context))
            )
        if category_tokens & {"casino", "gambling", "betting", "online_casino", "pyramid", "investment_pyramid", "scam"}:
            return True
        return bool(
            gambling_domain_signals(candidate.domain, candidate_context)
            or has_user_risk_search_context(candidate_context)
        )

    def _discover_from_bootstrap(self, seed_query: str | None, limit: int, search_mode: str = "auto") -> list[Candidate]:
        if limit <= 0:
            return []
        effective_mode = self._effective_search_mode(seed_query, search_mode)
        focus = (seed_query or " ".join(self.settings.seed_queries)).lower()
        normalized_focus = re.sub(r"[^a-zа-я0-9]+", " ", focus)
        wants_gambling = bool(re.search(r"(casino|казино|bet|бет|букмекер|ставк|зеркал|mirror)", normalized_focus))
        use_all = not seed_query or wants_gambling

        candidates: list[Candidate] = []
        for item in BOOTSTRAP_CANDIDATES:
            aliases = [str(alias).lower() for alias in item.get("aliases", [])]
            matched = use_all or any(alias in normalized_focus for alias in aliases)
            if not matched:
                continue
            domain = extract_domain(str(item["domain"]))
            if not is_candidate_domain(domain):
                continue
            item_category = self._bootstrap_item_category(item)
            if effective_mode == "casino" and item_category == "betting":
                continue
            candidates.append(
                Candidate(
                    url=normalize_url(domain),
                    domain=domain,
                    category=item_category,
                    why=(
                        "Bootstrap-кандидат: внешний поиск не дал достаточно доменов, "
                        "поэтому известный бренд/домен отправлен на техническую проверку."
                    ),
                    search_query=seed_query or "bootstrap brand candidates",
                    brand=str(item.get("brand") or "") or None,
                )
            )
            if len(candidates) >= limit:
                break
        return candidates

    def _discover_from_algorithmic_mirrors(
        self,
        seed_query: str | None,
        limit: int,
        excluded_domains: set[str],
        search_mode: str = "auto",
    ) -> list[Candidate]:
        if limit <= 0:
            return []
        effective_mode = self._effective_search_mode(seed_query, search_mode)
        focus = (seed_query or " ".join(self.settings.seed_queries)).lower()
        normalized_focus = re.sub(r"[^a-zа-я0-9]+", " ", focus)
        wants_gambling = bool(re.search(r"(casino|казино|bet|бет|букмекер|ставк|зеркал|mirror)", normalized_focus))
        use_all = not seed_query or wants_gambling
        seen = set(excluded_domains)
        candidates: list[Candidate] = []

        for item in BOOTSTRAP_CANDIDATES:
            aliases = [str(alias).lower() for alias in item.get("aliases", [])]
            matched = use_all or any(alias in normalized_focus for alias in aliases)
            if not matched:
                continue

            item_category = self._bootstrap_item_category(item)
            if effective_mode == "casino" and item_category == "betting":
                continue
            roots = self._brand_roots(item)
            for root in roots:
                for domain in self._mirror_domain_variants(root):
                    key = registered_domain(domain)
                    if not key or key in seen or not is_candidate_domain(key):
                        continue
                    seen.add(key)
                    candidates.append(
                        Candidate(
                            url=normalize_url(key),
                            domain=key,
                            category=item_category,
                            why=(
                                "Algorithmic-кандидат: домен похож на зеркало или региональную "
                                "вариацию известного risky-бренда и отправлен на живую проверку."
                            ),
                            search_query=seed_query or "algorithmic mirror expansion",
                            brand=str(item.get("brand") or "") or None,
                        )
                    )
                    if len(candidates) >= limit:
                        return candidates
        return candidates

    @staticmethod
    def _brand_roots(item: dict[str, Any]) -> list[str]:
        raw_values = [
            str(item.get("brand") or ""),
            extract_domain(str(item.get("domain") or "")).split(".", 1)[0],
            *[str(alias) for alias in item.get("aliases", [])],
        ]
        roots: list[str] = []
        for value in raw_values:
            clean = re.sub(r"[^a-z0-9]+", "", value.lower())
            if len(clean) < 3 or clean in roots:
                continue
            roots.append(clean)
        return roots[:4]

    @staticmethod
    def _mirror_domain_variants(root: str) -> list[str]:
        domains: list[str] = []
        for tld in MIRROR_TLDS:
            domains.append(f"{root}.{tld}")
            for modifier in MIRROR_MODIFIERS:
                domains.append(f"{root}-{modifier}.{tld}")
                domains.append(f"{root}{modifier}.{tld}")
                domains.append(f"{modifier}-{root}.{tld}")
        return domains[:180]

    def _discover_with_gemini(
        self,
        run_id: int,
        seed_query: str | None,
        max_candidates: int,
        search_mode: str = "auto",
    ) -> list[Candidate]:
        focus = seed_query.strip() if seed_query else " ; ".join(self.settings.seed_queries)
        prompt = f"""
Critical local-search behavior:
- Treat domains like pinco4.aktif.kz and top.45minut.kz only as examples of direct search-result patterns; do not hardcode them or filter by Kazakhstan.
- If Google/Gemini returns a redirect URL, unwrap it and return the real target domain, not google.com or vertexaisearch.cloud.google.com.
- Do not discard plain-looking .kz subdomains when the title/snippet/query context is casino, slots, mirror, or gambling.
- Primary task: reproduce what an ordinary browser user sees in search after typing the query. Prefer direct casino/pyramid sites from organic/ad-like search results over blacklist feeds, review articles, forums, and complaint databases.
- In casino mode, reject official bookmaker home domains unless the page is clearly an illegal mirror or a real casino/slots product; casino and pyramid targets have priority over betting.
- The target is the source website where a user can register, deposit, play, invest, or send money. A review, Telegram post, YouTube video, article, forum, catalog, or blacklist page is only a source_url, never the candidate.

Ты OSINT-следователь и имитируешь обычный пользовательский поиск в браузере. Нужно найти прямые домены сайтов, которые обычный человек реально увидит, если ищет онлайн-казино, слоты, рабочие зеркала, фишинг или инвестиционные пирамиды.
Используй Google Search grounding как браузерный поиск. Начинай с пользовательских запросов: "онлайн казино Казахстан", "казино онлайн играть", "слоты на деньги Казахстан", "рабочее зеркало казино", "казино зеркало вход", "инвестиции быстрый доход USDT", "Kaspi фишинг вход". Смотри прежде всего прямые результаты поиска, где пользователь может зайти, зарегистрироваться, внести деньги, играть или отправить деньги.
Ищи не только по названию бренда, но и по шаблонам "site scam", "withdraw problem", "не выводят деньги", "жалоба", "отзывы", "обман", "blacklist", "complaint", "report".
Полезные источники для расширения пула: поисковая выдача по пользовательским запросам. Публичные страницы жалоб, ScamAdviser/Trustpilot-style обзоры, форумы пострадавших и blacklist reports используй только как вспомогательные источники для извлечения прямого домена сайта-источника.
Важно: форум, новость, Telegram, YouTube, соцсеть или каталог не является кандидатом. Из таких страниц извлекай прямой домен подозрительного сайта и сохраняй страницу жалобы в source_urls.
1) онлайн-казино/беттинг без очевидной лицензии,
2) рабочие зеркала казино/беттинга,
3) инвестиционные лохотроны или фишинговые страницы.

Очень важно:
- Фокус: глобальный поиск, не только Казахстан. Нужны домены, которые реально открываются в браузере, включая рабочие зеркала.
- Не возвращай официальные банки, госуслуги, маркетплейсы и крупные легитимные сервисы: kaspi.kz, halykbank.kz, homebank.kz, egov.kz, gov.kz и похожие официальные домены.
- Если это букмекер без признаков casino/slots/roulette и без подтверждения нелегальности, ставь category="betting", а не "casino".
- Если это онлайн-казино, должны быть признаки реального игрового продукта: slots, roulette, blackjack, jackpot, live casino, регистрация/депозит/игровое лобби.
- Не возвращай домены, которые публично описаны как заблокированные и не имеют рабочего зеркала.
- НЕ возвращай IP-адреса.
- НЕ возвращай служебные URL Gemini/Google Search вроде vertexaisearch.cloud.google.com/grounding-api-redirect, google.com/url или google.com/search.
- НЕ возвращай статьи, новости, форумы, Telegram, YouTube, соцсети, GitHub, каталоги и справочники.
- Возвращай только прямой домен или URL подозрительного сайта, который можно открыть в браузере и зафиксировать скриншотом.
- Если уверен только частично, все равно объясни сигнал, но не обвиняй окончательно.
- Нужны живые домены, а не threat-feed строки.
- Верни не меньше {max_candidates} разных доменов, если они есть. Лучше дать запас кандидатов, потому что часть сайтов может не открыться.

Фокус поиска:
{focus}

Верни только JSON без Markdown:
{{
  "methodology": ["какие запросы использовал"],
  "candidates": [
    {{
      "url": "https://domain.example",
      "domain": "domain.example",
      "category": "casino|gambling|phishing|scam|pyramid|suspicious",
      "why": "коротко: почему домен выглядит подозрительно",
      "search_query": "поисковый запрос, которым найдено",
      "source_urls": ["https://public-source.example/page"],
      "mirror_hints": ["other-domain.example"],
      "brand": "название бренда если понятно"
    }}
  ]
}}
"""
        self.db.add_log(run_id, "info", "Ищу сайты через Gemini Search", {"limit": max_candidates})
        data, meta = self.gemini.generate_json(
            prompt,
            use_search=True,
            temperature=0.2,
            max_attempts=max(1, len(self.settings.gemini_api_keys) * len(self.settings.gemini_models)),
            retry_sleep=False,
        )
        grounding_sources = meta.get("grounding_sources", [])
        raw_items = data.get("candidates", []) or []
        self.db.add_log(
            run_id,
            "info",
            "Gemini вернул список для проверки",
            {"items": len(raw_items), "sources": len(grounding_sources), "model": meta.get("model"), "key_hash": meta.get("key_hash")},
        )

        candidates: list[Candidate] = []
        skipped_technical = 0
        for item in raw_items:
            candidate = self._candidate_from_item(item, default_sources=grounding_sources)
            if candidate:
                candidates.append(candidate)
            else:
                skipped_technical += 1
        candidates.extend(self._candidates_from_grounding_sources(grounding_sources, focus, search_mode))
        if skipped_technical:
            self.db.add_log(
                run_id,
                "warning",
                "Технические или неподходящие URL от Gemini пропущены",
                {"count": skipped_technical},
            )
        return candidates

    def _candidates_from_grounding_sources(
        self,
        grounding_sources: list[dict[str, str]],
        focus: str,
        search_mode: str = "auto",
    ) -> list[Candidate]:
        candidates: list[Candidate] = []
        context = f"{focus} " + " ".join(
            f"{source.get('title', '')} {source.get('url', '')}" for source in grounding_sources
        )
        if not has_user_risk_search_context(context):
            return candidates
        search_mode = self._effective_search_mode(focus, search_mode)
        for source in grounding_sources:
            url = str(source.get("url") or "")
            title = str(source.get("title") or "")
            source_context = f"{title} {url}"
            category = self._category_from_search_result(source_context)
            candidate = self._candidate_from_item(
                {
                    "url": url,
                    "title": title,
                    "category": category,
                    "why": "Домен найден как прямой результат пользовательского Google-поиска через Gemini Search grounding.",
                    "search_query": focus,
                    "source_urls": [url],
                },
                default_sources=[],
            )
            if not candidate:
                continue
            if self._is_informational_search_result(candidate.url, f"{focus} {source_context}", search_mode):
                continue
            if not gambling_domain_signals(candidate.domain, f"{focus} {source_context}") and candidate.category in {"casino", "gambling"}:
                candidate.category = "suspicious"
            if not self._candidate_matches_user_search(candidate, focus, search_mode):
                continue
            candidates.append(candidate)
        return self._sort_candidates_for_search_mode(candidates, search_mode)

    async def _discover_from_plain_feeds_legacy(self, run_id: int, max_candidates: int) -> list[Candidate]:
        candidates: list[Candidate] = []
        timeout = min(self.settings.request_timeout_seconds, 15)
        headers = {"User-Agent": self.settings.user_agent}
        async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
            for feed_url in self.settings.osint_feeds:
                if len(candidates) >= max_candidates:
                    break
                try:
                    response = await client.get(feed_url)
                    response.raise_for_status()
                except Exception as exc:  # noqa: BLE001
                    self.db.add_log(run_id, "warning", "OSINT feed недоступен", {"url": feed_url, "error": str(exc)})
                    continue

                added = 0
                skipped = 0
                for line in response.text.splitlines():
                    if len(candidates) >= max_candidates:
                        break
                    text = line.strip()
                    if not text or text.startswith("#"):
                        continue
                    domain = extract_domain(text)
                    if not is_candidate_domain(domain):
                        skipped += 1
                        continue
                    candidates.append(
                        Candidate(
                            url=normalize_url(text),
                            domain=domain,
                            category="phishing" if "phish" in feed_url.lower() else "suspicious",
                            why=f"Домен найден в публичном OSINT feed: {feed_url}",
                            search_query="public OSINT feed",
                            source_urls=[feed_url],
                        )
                    )
                    added += 1
                self.db.add_log(run_id, "info", "OSINT feed обработан", {"url": feed_url, "added": added, "skipped": skipped})
        return candidates

    async def _discover_from_feeds(self, run_id: int, max_candidates: int) -> list[Candidate]:
        candidates: list[Candidate] = []
        seen: set[str] = set()
        timeout = min(self.settings.request_timeout_seconds, 15)
        headers = {"User-Agent": self.settings.user_agent}
        sources = self._osint_sources()

        self.db.add_log(run_id, "info", "OSINT discovery started", {"sources": len(sources), "limit": max_candidates})
        async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
            for source in sources:
                if len(candidates) >= max_candidates:
                    break
                try:
                    response = await client.get(source["url"])
                    response.raise_for_status()
                except Exception as exc:  # noqa: BLE001
                    self.db.add_log(
                        run_id,
                        "warning",
                        "OSINT source unavailable",
                        {"name": source["name"], "url": source["url"], "error": str(exc)},
                    )
                    continue

                added = 0
                skipped = 0
                for token in self._feed_tokens(response.text, source["parser"]):
                    if len(candidates) >= max_candidates:
                        break
                    domain = extract_domain(token)
                    if not is_candidate_domain(domain):
                        skipped += 1
                        continue
                    key = registered_domain(domain)
                    if not key or key in seen:
                        skipped += 1
                        continue
                    seen.add(key)
                    candidates.append(
                        Candidate(
                            url=normalize_url(token or domain),
                            domain=domain,
                            category=source["category"],
                            why=f"Domain found in CyberScan-style OSINT source: {source['name']}.",
                            search_query=f"OSINT feed: {source['name']}",
                            source_urls=[source["url"]],
                        )
                    )
                    added += 1
                self.db.add_log(
                    run_id,
                    "info",
                    "OSINT source processed",
                    {"name": source["name"], "category": source["category"], "added": added, "skipped": skipped},
                )
        return candidates

    def _osint_sources(self) -> list[dict[str, str]]:
        sources = [dict(item) for item in CYBERSCAN_OSINT_SOURCES]
        known_urls = {item["url"] for item in sources}
        for feed_url in self.settings.osint_feeds:
            if feed_url in known_urls:
                continue
            known_urls.add(feed_url)
            sources.append(
                {
                    "name": extract_domain(feed_url) or "custom_feed",
                    "url": feed_url,
                    "category": "phishing" if "phish" in feed_url.lower() else "suspicious",
                    "parser": "plain_list",
                }
            )
        return sources

    def _feed_tokens(self, text: str, parser: str) -> list[str]:
        if parser == "csv":
            tokens: list[str] = []
            rows = csv.reader(StringIO("\n".join(line for line in text.splitlines() if not line.startswith("#"))))
            for row in rows:
                for cell in row:
                    tokens.extend(self._domains_or_urls_from_text(cell))
            return tokens

        tokens = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", "!", "//")):
                continue
            line = line.split("#", 1)[0].strip()
            if parser == "hosts_file":
                parts = [part.strip() for part in line.split() if part.strip()]
                line_tokens = [part for part in parts[1:] if "." in part] if len(parts) > 1 else parts
            else:
                line_tokens = [line]
            for token in line_tokens:
                tokens.extend(self._domains_or_urls_from_text(token))
        return tokens

    @staticmethod
    def _domains_or_urls_from_text(text: str) -> list[str]:
        cleaned = text.strip().strip('"').strip("'").strip(",")
        if not cleaned:
            return []
        urls = [
            normalize_url(unwrap_known_redirect_url(url) or url)
            for url in re.findall(r"(?i)https?://[^\s,\"'<>]+", cleaned)
            if is_candidate_url(unwrap_known_redirect_url(url) or url)
        ]
        if urls:
            return urls
        domains = [
            domain
            for domain in re.findall(r"(?i)(?:[a-z0-9-]+\.)+[a-z]{2,24}", cleaned)
            if is_candidate_domain(domain)
        ]
        if cleaned.startswith("||"):
            domains.append(cleaned[2:].strip("^/"))
        if not urls and not domains and is_candidate_domain(extract_domain(cleaned)):
            domains.append(cleaned)
        return [*urls, *domains]

    async def _discover_mirrors(
        self,
        run_id: int,
        candidates: list[Candidate],
        search_mode: str = "auto",
    ) -> list[dict[str, Any]]:
        effective_mode = self.normalize_search_mode(search_mode)
        casino_candidates = [
            candidate
            for candidate in candidates
            if candidate.category.lower() in {"casino", "gambling", "betting", "suspicious"}
            and (
                effective_mode != "casino"
                or (
                    candidate.category.lower() != "betting"
                    and not self._is_bookmaker_first_context(" ".join([candidate.domain, candidate.url, candidate.why]))
                )
            )
        ][: self.settings.max_mirror_checks_per_run]

        groups: list[dict[str, Any]] = []
        if not casino_candidates:
            return groups
        if not self.gemini.available:
            self.db.add_log(run_id, "warning", "Поиск зеркал пропущен: Gemini ключ не настроен")
            return groups

        domains = [candidate.domain for candidate in casino_candidates if is_candidate_domain(candidate.domain)]
        if not domains:
            return groups

        prompt = f"""
Найди возможные зеркальные домены для этих casino/betting/scam сайтов.
Используй только публичный поиск. Не возвращай IP, статьи, соцсети и каталоги.

Домены:
{", ".join(domains)}

Верни только JSON без Markdown:
{{
  "mirror_groups": [
    {{
      "brand": "brand-or-domain",
      "domains": ["domain1.com", "domain2.com"],
      "why": "что связывает домены",
      "source_urls": ["https://public-source.example"]
    }}
  ]
}}
"""
        try:
            data, meta = self.gemini.generate_json(
                prompt,
                use_search=True,
                temperature=0.1,
                max_attempts=max(1, len(self.settings.gemini_api_keys) * len(self.settings.gemini_models)),
                retry_sleep=False,
            )
        except GeminiQuotaError as exc:
            self.db.add_log(run_id, "warning", "Лимит Gemini для поиска зеркал исчерпан", {"error": str(exc)})
            return groups
        except Exception as exc:  # noqa: BLE001
            self.db.add_log(run_id, "warning", "Поиск зеркал не дал результата", {"error": str(exc)})
            return groups

        grounding_sources = meta.get("grounding_sources", [])
        for group in data.get("mirror_groups", []) or []:
            domains = sorted({extract_domain(domain) for domain in group.get("domains", []) if is_candidate_domain(extract_domain(domain))})
            if not domains:
                continue
            groups.append(
                {
                    "brand": group.get("brand") or domains[0],
                    "domains": domains,
                    "why": group.get("why") or "",
                    "source_urls": group.get("source_urls") or grounding_sources,
                }
            )
        self.db.add_log(run_id, "info", "Зеркальные группы проверены", {"count": len(groups), "model": meta.get("model")})
        return groups

    async def _build_finding(
        self,
        run_id: int,
        candidate: Candidate,
        mirror_group: str | None,
        take_screenshots: bool,
        search_mode: str = "auto",
    ) -> dict[str, Any]:
        evidence = await self.evidence.collect(candidate.url, run_id)
        domain = evidence.domain or candidate.domain
        if not is_candidate_domain(domain):
            return {
                "_skip": True,
                "_skip_reason": "это IP, непубличный или технический домен",
                "url": candidate.url,
                "domain": domain,
                "status_code": evidence.status_code,
            }
        status_code = int(evidence.status_code or 0)
        if not evidence.active or not evidence.final_url or status_code < 200 or status_code >= 400:
            skip_reason = "сайт не открылся с нормальным HTTP 2xx/3xx"
            if evidence.blocked_by_policy:
                skip_reason = "blocked/restricted access page; site is not treated as reachable"
            return {
                "_skip": True,
                "_skip_reason": skip_reason,
                "url": candidate.url,
                "domain": domain,
                "status_code": evidence.status_code,
            }
        if not evidence.html_path:
            self.db.add_log(
                run_id,
                "warning",
                "HTML не сохранен, продолжаю проверку по HTTP/DNS/TLS данным",
                {"domain": domain, "status_code": evidence.status_code, "page_size_bytes": evidence.page_size_bytes},
            )

        source_urls = self._clean_sources(candidate.source_urls)
        content_ai = self.content_ai.analyze(candidate.url, evidence)
        content_skip = self._content_skip_reason(content_ai, evidence, candidate, search_mode)
        if content_skip:
            self.db.add_log(
                run_id,
                "warning",
                "Сайт пропущен после контентной проверки",
                {"domain": domain, "reason": content_skip, "category": content_ai.get("category_hint")},
            )
            return {
                "_skip": True,
                "_skip_reason": content_skip,
                "url": candidate.url,
                "domain": domain,
                "status_code": evidence.status_code,
            }

        screenshot_path = None
        screenshot_error = None
        if take_screenshots and evidence.final_url:
            self.db.add_log(run_id, "info", "Делаю скриншот сайта", {"domain": domain, "url": evidence.final_url})
            screenshot = await self.screenshots.capture(
                evidence.final_url,
                run_id,
                title=evidence.title,
                html_path=evidence.html_path,
                status_code=evidence.status_code,
            )
            screenshot_path = screenshot.path
            screenshot_error = screenshot.error
            if screenshot_path:
                if screenshot_error:
                    self.db.add_log(
                        run_id,
                        "warning",
                        "Скриншот сохранен с предупреждением",
                        {"domain": domain, "path": screenshot_path, "warning": screenshot_error},
                    )
                else:
                    self.db.add_log(run_id, "info", "Скриншот сохранен", {"domain": domain, "path": screenshot_path})
            elif screenshot_error:
                self.db.add_log(run_id, "warning", "Скриншот не сохранен", {"domain": domain, "error": screenshot_error})
        elif not take_screenshots:
            self.db.add_log(run_id, "info", "Скриншот пропущен: выключен в запуске", {"domain": domain})

        cyberscan_result = self.cyberscan.classify(candidate.url, evidence, content_ai)
        if cyberscan_result.get("available"):
            self.db.add_log(
                run_id,
                "info",
                "CyberScan ML classification completed",
                {
                    "domain": domain,
                    "label": cyberscan_result.get("label"),
                    "suspicious_probability": cyberscan_result.get("suspicious_probability"),
                },
            )
        elif cyberscan_result.get("error"):
            self.db.add_log(
                run_id,
                "warning",
                "CyberScan ML unavailable",
                {"domain": domain, "error": cyberscan_result.get("error")},
            )

        ml_result = self.ml.classify(candidate.url, evidence)
        if ml_result.get("available"):
            self.db.add_log(
                run_id,
                "info",
                "ML классификация сайта завершена",
                {
                    "domain": domain,
                    "label": ml_result.get("label"),
                    "confidence": ml_result.get("confidence"),
                    "model": ml_result.get("model"),
                },
            )
        elif ml_result.get("error"):
            self.db.add_log(
                run_id,
                "warning",
                "ML классификация недоступна",
                {"domain": domain, "error": ml_result.get("error")},
            )

        category = self._category_with_ai(candidate.category or "suspicious", ml_result, cyberscan_result, content_ai)
        risk, verdict, reasons = score_finding(
            category=category,
            active=evidence.active,
            status_code=evidence.status_code,
            keyword_hits=evidence.keyword_hits,
            has_sources=bool(source_urls),
            domain=domain,
            mirror_group=mirror_group,
        )
        risk = min(
            100,
            risk
            + int(content_ai.get("risk_delta") or 0)
            + self._ml_risk_delta(ml_result)
            + self._cyberscan_risk_delta(cyberscan_result),
        )
        technical_delta, technical_reasons = self._technical_risk_signals(evidence)
        risk = max(0, min(100, risk + technical_delta))
        risk = self._apply_policy_caps(risk, category, content_ai)
        risk = min(95, risk)
        verdict = self._verdict_for_risk(risk)
        if candidate.why:
            reasons.insert(0, candidate.why)
        for signal in reversed(technical_reasons):
            reasons.insert(1 if candidate.why else 0, signal)
        for signal in reversed(content_ai.get("signals") or []):
            reasons.insert(1 if candidate.why else 0, str(signal))
        cyberscan_reason = self._cyberscan_reason(cyberscan_result)
        if cyberscan_reason:
            reasons.insert(1 if candidate.why else 0, cyberscan_reason)
        ml_reason = self._ml_reason(ml_result)
        if ml_reason:
            reasons.insert(1 if candidate.why else 0, ml_reason)
        if screenshot_error:
            if screenshot_path:
                reasons.append(f"Screenshot saved with warning: {screenshot_error}")
            else:
                reasons.append(f"Screenshot not saved: {screenshot_error}")
        if not evidence.html_path:
            reasons.append("HTML не сохранен, но сайт ответил нормальным HTTP-кодом; DNS/TLS/скорость/редиректы зафиксированы.")
        if evidence.tls and not evidence.tls.get("valid"):
            reasons.append("SSL/TLS сертификат отсутствует или недействителен; сайт все равно зафиксирован как рабочий по HTTP-доступности.")
        reasons = self._compact_reasons(reasons)

        return {
            "url": candidate.url,
            "final_url": evidence.final_url,
            "domain": domain,
            "normalized_domain": registered_domain(domain),
            "title": evidence.title,
            "category": category,
            "verdict": verdict,
            "risk_score": risk,
            "active": evidence.active,
            "status_code": evidence.status_code,
            "mirror_group": mirror_group,
            "screenshot_path": screenshot_path,
            "html_path": evidence.html_path,
            "html_sha256": evidence.html_sha256,
            "dns_json": evidence.dns,
            "tls_json": evidence.tls,
            "evidence_json": {
                **evidence.as_evidence(),
                "search_query": candidate.search_query,
                "brand": candidate.brand,
                "mirror_hints": candidate.mirror_hints,
                "ml": ml_result,
                "cyberscan_ml": cyberscan_result,
                "content_ai": content_ai,
                "screenshot_error": screenshot_error,
            },
            "sources_json": [{"url": url} for url in source_urls],
            "reasons_json": reasons,
        }

    @staticmethod
    def _content_skip_reason(
        content_ai: dict[str, Any],
        evidence: Any,
        candidate: Candidate | None = None,
        search_mode: str | None = "auto",
    ) -> str | None:
        search_mode = Investigator.normalize_search_mode(search_mode)
        quality = content_ai.get("site_quality") or {}
        has_domain_signals = bool(
            content_ai.get("casino_keywords")
            or content_ai.get("betting_keywords")
            or content_ai.get("pyramid_keywords")
            or content_ai.get("brand_impersonation")
            or content_ai.get("domain_gambling_signals")
        )
        candidate_category = (candidate.category if candidate else "").lower()
        candidate_context = " ".join(
            [
                candidate.domain if candidate else "",
                candidate.search_query if candidate else "",
                candidate.why if candidate else "",
            ]
        )
        source_supports_gambling = bool(
            candidate
            and (
                set(re.split(r"[^a-z_]+", candidate_category)) & {"casino", "gambling", "betting"}
                or gambling_domain_signals(candidate.domain, candidate_context)
            )
        )
        if getattr(evidence, "blocked_by_policy", False) or quality.get("is_blocked_or_restricted") or Investigator._looks_like_blocked_page(content_ai, evidence):
            return "blocked/restricted access page; not a reachable user-facing target"
        if quality.get("is_empty_or_parked") and (quality.get("markers") or not has_domain_signals):
            return "страница пустая, parking/placeholder или не содержит полезного контента"
        if search_mode == "casino":
            final_url = str(getattr(evidence, "final_url", "") or "")
            if candidate and (
                Investigator._is_official_bookmaker_domain(candidate.domain)
                or Investigator._is_official_bookmaker_domain(final_url or candidate.url)
            ):
                return "casino mode: official bookmaker domain, not a casino/mirror target"
            if candidate and Investigator._is_bookmaker_first_context(
                " ".join([candidate.domain, candidate.url, candidate.why, final_url])
            ):
                return "casino mode: betting-first brand, not a pure casino target"
            content_label = str(content_ai.get("category_hint") or "").lower()
            casino_hits = content_ai.get("casino_keywords") or []
            betting_hits = content_ai.get("betting_keywords") or []
            pyramid_hits = content_ai.get("pyramid_keywords") or []
            casino_context = " ".join(
                [
                    candidate.url if candidate else "",
                    candidate.domain if candidate else "",
                    str(getattr(evidence, "final_url", "") or ""),
                    " ".join(str(hit) for hit in casino_hits),
                ]
            )
            has_casino_product = bool(
                content_label == "online_casino"
                or casino_hits
                or Investigator._has_casino_product_signal(casino_context)
            )
            if not has_casino_product and (content_label == "investment_pyramid" or pyramid_hits):
                return None
            if not has_casino_product and (content_label == "sports_betting_review" or betting_hits):
                return "режим casino: букмекерская/ставочная страница без признаков онлайн-казино"
            if not has_casino_product and candidate and candidate.category in {"betting", "gambling"}:
                return "режим casino: кандидат похож на betting, но не на casino/slots"
            if not has_casino_product:
                return "режим casino: на странице нет признаков онлайн-казино, слотов или игрового лобби"
        if source_supports_gambling:
            return None
        if quality.get("quality") == "thin_content" and not has_domain_signals:
            return "страница слишком пустая для реестра: нет контента и нет сильных признаков риска"
        if not getattr(evidence, "html_path", None) and int(getattr(evidence, "page_size_bytes", 0) or 0) < 1500 and not has_domain_signals:
            return "ответ сайта слишком мал и HTML не сохранен; кандидат похож на пустышку"
        return None

    @staticmethod
    def _technical_risk_signals(evidence: Any) -> tuple[int, list[str]]:
        delta = 0
        reasons: list[str] = []
        domain_info = evidence.domain_info or {}
        dns = evidence.dns or {}
        tls = evidence.tls or {}

        age = domain_info.get("age_days")
        try:
            age_days = int(age) if age is not None else None
        except (TypeError, ValueError):
            age_days = None
        if age_days is not None:
            if age_days >= 0 and age_days <= 30:
                delta += 15
                reasons.append(f"Домен очень молодой: {age_days} дн.; это сильный признак одноразовой инфраструктуры.")
            elif age_days <= 180:
                delta += 8
                reasons.append(f"Домен зарегистрирован недавно: {age_days} дн.; требуется повышенная проверка.")

        registrar = str(domain_info.get("registrar") or "")
        privacy_text = " ".join(
            str(domain_info.get(key) or "")
            for key in ("privacy", "is_private", "registrant", "org", "organization")
        ).lower()
        if any(token in privacy_text for token in ("privacy", "redacted", "private", "whoisguard")):
            delta += 5
            reasons.append("WHOIS выглядит скрытым или редактированным; владелец домена не прозрачен.")
        if registrar:
            reasons.append(f"WHOIS registrar: {registrar}.")

        mx_records = dns.get("mx_records") or []
        if not mx_records:
            delta += 3
            reasons.append("MX-записи не найдены; для одноразовых доменов это частый технический паттерн.")

        if tls:
            issuer = str(tls.get("issuer") or "").lower()
            subject = str(tls.get("subject") or "").lower()
            if not tls.get("valid"):
                delta += 8
                reasons.append("SSL/TLS не подтвержден или отсутствует; это не доказывает фишинг, но усиливает технический риск.")
            if issuer and subject and issuer == subject:
                delta += 10
                reasons.append("SSL/TLS самоподписанный; это сильный технический сигнал риска.")
            try:
                days_left = int(tls.get("expires_in_days"))
            except (TypeError, ValueError):
                days_left = None
            if days_left is not None and 0 <= days_left <= 7:
                delta += 4
                reasons.append(f"SSL/TLS истекает очень скоро: {days_left} дн.; фиксируется как технический риск.")

        return delta, reasons

    @staticmethod
    def _apply_policy_caps(risk: int, category: str, content_ai: dict[str, Any]) -> int:
        policy = content_ai.get("domain_policy") or {}
        credential_risk = bool(content_ai.get("credential_risk"))
        category_lower = (category or "").lower()
        if policy.get("trusted") and category_lower != "phishing" and not credential_risk:
            return max(0, min(35, risk))
        if category_lower == "sports_betting_review":
            return max(0, min(72, risk))
        if category_lower == "empty_or_parked":
            return max(0, min(25, risk))
        return risk

    def _category_with_ai(
        self,
        category: str,
        ml_result: dict[str, Any],
        cyberscan_result: dict[str, Any],
        content_ai: dict[str, Any],
    ) -> str:
        content_label = str(content_ai.get("category_hint") or "").lower()
        content_confidence = str(content_ai.get("category_confidence") or "low").lower()
        policy = content_ai.get("domain_policy") or {}
        if policy.get("trusted") and content_label != "phishing":
            return "legit"
        strong_content_labels = {
            "online_casino",
            "sports_betting_review",
            "investment_pyramid",
            "phishing",
            "suspicious",
            "empty_or_parked",
            "legit",
        }
        if content_label in strong_content_labels and content_confidence in {"medium", "high"}:
            return content_label

        ml_label = str(ml_result.get("label") or "").lower()
        ml_confidence = float(ml_result.get("confidence") or 0)
        if ml_label == "legit" and ml_confidence >= 0.75 and content_confidence == "low":
            return "legit"

        ml_category = self._category_with_ml(category, ml_result)
        if ml_category != category:
            return ml_category

        cyber_label = str(cyberscan_result.get("label") or "").lower()
        cyber_probability = float(cyberscan_result.get("suspicious_probability") or 0)
        weak_category = category.lower() in {"", "manual", "unknown", "suspicious"}
        if cyber_label == "suspicious" and cyber_probability >= 0.68 and weak_category:
            return "suspicious"
        return category

    def _category_with_ml(self, category: str, ml_result: dict[str, Any]) -> str:
        label = str(ml_result.get("label") or "").lower()
        confidence = float(ml_result.get("confidence") or 0)
        if label not in {"phishing", "casino", "pyramid", "suspicious"}:
            return category
        weak_category = category.lower() in {"", "manual", "unknown", "suspicious"}
        label_map = {"casino": "online_casino", "pyramid": "investment_pyramid"}
        mapped_label = label_map.get(label, label)
        if confidence >= self.settings.ml_min_confidence and (weak_category or confidence >= 0.65):
            return mapped_label
        return category

    @staticmethod
    def _ml_risk_delta(ml_result: dict[str, Any]) -> int:
        if not ml_result.get("available"):
            return 0
        label = str(ml_result.get("label") or "").lower()
        confidence = float(ml_result.get("confidence") or 0)
        if label == "legit":
            if confidence >= 0.85:
                return -24
            if confidence >= 0.70:
                return -16
            if confidence >= 0.58:
                return -8
            return 0
        if label in {"phishing", "casino", "pyramid"}:
            if confidence >= 0.85:
                return 16
            if confidence >= 0.68:
                return 10
            if confidence >= 0.55:
                return 5
        if label == "suspicious" and confidence >= 0.70:
            return 8
        return 0

    @staticmethod
    def _cyberscan_risk_delta(cyberscan_result: dict[str, Any]) -> int:
        if not cyberscan_result.get("available"):
            return 0
        label = str(cyberscan_result.get("label") or "").lower()
        probability = float(cyberscan_result.get("suspicious_probability") or 0)
        if label == "legit" or probability <= 0.30:
            return -8 if probability <= 0.22 else -4
        if probability >= 0.85:
            return 18
        if probability >= 0.68:
            return 12
        if probability >= 0.55:
            return 6
        return 0

    @classmethod
    def _cyberscan_reason(cls, cyberscan_result: dict[str, Any]) -> str | None:
        if not cyberscan_result.get("available"):
            return None
        label = str(cyberscan_result.get("label") or "").lower()
        probability = float(cyberscan_result.get("suspicious_probability") or 0)
        top = cls._readable_feature_list(cyberscan_result.get("top_features", []), limit=4)
        details = f"; главные сигналы: {', '.join(top)}" if top else ""
        if label == "legit" or probability <= 0.30:
            return f"CyberScan ML не видит сильных признаков мошенничества: подозрительность {probability:.0%}{details}."
        return f"CyberScan ML оценил подозрительность сайта как {probability:.0%}{details}."

    @staticmethod
    def _verdict_for_risk(risk: int) -> str:
        if risk >= 80:
            return "suspected_fraud_or_illegal"
        if risk >= 60:
            return "suspicious"
        if risk >= 40:
            return "needs_review"
        return "low_signal"

    @classmethod
    def _ml_reason(cls, ml_result: dict[str, Any]) -> str | None:
        if not ml_result.get("available"):
            return None
        label = str(ml_result.get("label") or "unknown")
        confidence = float(ml_result.get("confidence") or 0)
        display_label = CATEGORY_DISPLAY.get(label.lower(), label)
        top = cls._readable_feature_list(ml_result.get("top_features", []), limit=4)
        details = f"; главные сигналы: {', '.join(top)}" if top else ""
        if label.lower() == "legit":
            return f"CatBoost считает сайт похожим на обычный: уверенность {confidence:.0%}{details}."
        return f"CatBoost относит сайт к категории «{display_label}»: уверенность {confidence:.0%}{details}."

    @staticmethod
    def _readable_feature_list(features: Any, *, limit: int = 4) -> list[str]:
        if not isinstance(features, list):
            return []
        readable: list[str] = []
        for item in features:
            if not isinstance(item, dict):
                continue
            name = str(item.get("label") or FEATURE_DISPLAY.get(str(item.get("feature") or ""), item.get("feature") or ""))
            if not name or name in readable:
                continue
            readable.append(name)
            if len(readable) >= limit:
                break
        return readable

    @staticmethod
    def _compact_reasons(reasons: list[Any], *, limit: int = 14) -> list[str]:
        compact: list[str] = []
        seen: set[str] = set()
        for reason in reasons:
            text = str(reason or "").strip()
            if not text:
                continue
            key = re.sub(r"\s+", " ", text).casefold()
            if key in seen:
                continue
            seen.add(key)
            compact.append(text)
            if len(compact) >= limit:
                break
        return compact

    def _candidate_from_item(
        self,
        item: dict[str, Any],
        default_sources: list[dict[str, str]],
    ) -> Candidate | None:
        text_blob = self._item_text_blob(item, default_sources)
        category_item = {key: value for key, value in item.items() if key != "search_query"}
        category_text_blob = self._item_text_blob(category_item, default_sources)
        url = unwrap_known_redirect_url(str(item.get("url") or item.get("domain") or "").strip())
        domain = extract_domain(item.get("domain") or url)
        domain_candidates = self._candidate_domains_from_text(text_blob)
        if self._is_non_target_source_domain(domain):
            domain = next((candidate for candidate in domain_candidates if not self._is_non_target_source_domain(candidate)), "")
        if not is_candidate_domain(domain):
            domain = next((candidate for candidate in domain_candidates if not self._is_non_target_source_domain(candidate)), "")
        if not is_candidate_domain(domain):
            return None
        normalized_url = normalize_url(url or domain)
        normalized_url_domain = extract_domain(normalized_url)
        if (
            not is_candidate_url(normalized_url)
            or normalized_url_domain != domain
            or self._is_non_target_source_domain(normalized_url_domain)
        ):
            if is_candidate_domain(domain):
                normalized_url = normalize_url(domain)
            else:
                return None
        sources = item.get("source_urls") or []
        if isinstance(sources, str):
            sources = [sources]
        if not sources:
            sources = [source["url"] for source in default_sources if source.get("url")]
        mirrors = item.get("mirror_hints") or []
        if isinstance(mirrors, str):
            mirrors = [mirrors]
        mirror_hints = [extract_domain(str(mirror)) for mirror in mirrors]
        mirror_hints = [domain for domain in [*mirror_hints, *domain_candidates] if is_candidate_domain(domain)]
        mirror_hints = sorted({hint for hint in mirror_hints if hint != domain})
        category = self._category_from_domain_context(domain, category_text_blob, str(item.get("category") or "suspicious").lower())
        why = str(item.get("why") or "")
        domain_signals = gambling_domain_signals(domain, category_text_blob)
        if domain_signals and not why:
            why = "Домен похож на casino/mirror результат поисковой выдачи: " + "; ".join(domain_signals[:3])
        return Candidate(
            url=normalized_url,
            domain=domain,
            category=category,
            why=why,
            search_query=str(item.get("search_query") or ""),
            source_urls=self._clean_sources(sources),
            mirror_hints=mirror_hints,
            brand=str(item.get("brand") or "") or None,
        )

    @staticmethod
    def _item_text_blob(item: dict[str, Any], default_sources: list[dict[str, str]]) -> str:
        parts: list[str] = []

        def collect(value: Any) -> None:
            if isinstance(value, dict):
                for nested in value.values():
                    collect(nested)
            elif isinstance(value, (list, tuple, set)):
                for nested in value:
                    collect(nested)
            elif value is not None:
                parts.append(str(value))

        collect(item)
        collect(default_sources)
        return " ".join(parts)

    @staticmethod
    def _candidate_domains_from_text(text: str) -> list[str]:
        domains: list[str] = []
        for raw_url in re.findall(r"(?i)https?://[^\s,\"'<>]+", text or ""):
            domain = extract_domain(unwrap_known_redirect_url(raw_url) or raw_url)
            if is_candidate_domain(domain):
                domains.append(domain)
        for raw_domain in re.findall(r"(?i)(?:[a-z0-9-]+\.)+[a-z]{2,24}", text or ""):
            domain = extract_domain(raw_domain)
            if is_candidate_domain(domain):
                domains.append(domain)
        return list(dict.fromkeys(domains))

    @staticmethod
    def _category_from_domain_context(domain: str, context: str, fallback: str) -> str:
        fallback = (fallback or "suspicious").lower()
        if fallback not in {"suspicious", "manual", "unknown", ""}:
            return fallback
        if not gambling_domain_signals(domain, context):
            return fallback or "suspicious"
        return "casino" if has_casino_context(context) else "gambling"

    @staticmethod
    def _is_non_target_source_domain(domain: str) -> bool:
        domain = extract_domain(domain)
        if not domain:
            return False
        return registered_domain(domain) in NON_TARGET_REGISTERED_DOMAINS

    def _dedupe_candidates(self, candidates: list[Candidate], limit: int) -> list[Candidate]:
        by_key: dict[str, Candidate] = {}
        for candidate in candidates:
            if not is_candidate_domain(candidate.domain) or not is_candidate_url(candidate.url):
                continue
            key = candidate.key()
            if not key:
                continue
            if key not in by_key:
                by_key[key] = candidate
                continue
            existing = by_key[key]
            existing.source_urls = self._clean_sources([*existing.source_urls, *candidate.source_urls])
            existing.mirror_hints = sorted(set([*existing.mirror_hints, *candidate.mirror_hints]))
            if not existing.why and candidate.why:
                existing.why = candidate.why
            if existing.category == "suspicious" and candidate.category != "suspicious":
                existing.category = candidate.category
        return list(by_key.values())[:limit]

    @staticmethod
    def _exclude_known_candidates(
        candidates: list[Candidate],
        known_domains: set[str],
    ) -> tuple[list[Candidate], int]:
        if not known_domains:
            return candidates, 0
        fresh: list[Candidate] = []
        skipped = 0
        for candidate in candidates:
            key = candidate.key()
            if key in known_domains:
                skipped += 1
                continue
            fresh.append(candidate)
        return fresh, skipped

    def _mirror_group_for(
        self,
        candidate: Candidate,
        all_candidates: list[Candidate],
        mirror_groups: list[dict[str, Any]],
    ) -> str | None:
        for group in mirror_groups:
            domains = [domain for domain in group.get("domains", []) if is_candidate_domain(domain)]
            registered = {registered_domain(domain) for domain in domains}
            if candidate.domain in domains or registered_domain(candidate.domain) in registered:
                return str(group.get("brand") or candidate.domain)

        related = [
            other.domain
            for other in all_candidates
            if other.domain != candidate.domain and likely_related_domains(candidate.domain, other.domain)
        ]
        if related:
            return f"похожий домен: {registered_domain(candidate.domain)}"
        return None

    @staticmethod
    def _clean_sources(sources: list[Any]) -> list[str]:
        cleaned: list[str] = []
        for source in sources:
            url = str(source).strip()
            if not url or url in cleaned:
                continue
            if is_technical_url(url):
                continue
            if url.startswith("http://") or url.startswith("https://"):
                cleaned.append(url)
        return cleaned[:20]





