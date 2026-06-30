#!/usr/bin/env python3
"""Build a free, source-driven cybersecurity event calendar.

The script intentionally uses only Python standard-library modules so it can
run on a clean machine without paid APIs or package installation.
"""

from __future__ import annotations

import csv
import hashlib
import html
import json
import re
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

try:
    from dateutil import parser as date_parser
except ModuleNotFoundError:
    class _FallbackDateParser:
        _FORMATS = (
            "%Y-%m-%d",
            "%Y/%m/%d",
            "%m/%d/%Y",
            "%m/%d/%y",
            "%B %d, %Y",
            "%b %d, %Y",
            "%B %d %Y",
            "%b %d %Y",
            "%A, %B %d, %Y",
            "%a, %b %d, %Y",
            "%A %B %d, %Y",
            "%a %b %d, %Y",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%d %I:%M %p",
            "%m/%d/%Y %H:%M",
            "%m/%d/%Y %I:%M %p",
            "%B %d, %Y %H:%M",
            "%B %d, %Y %I:%M %p",
            "%b %d, %Y %H:%M",
            "%b %d, %Y %I:%M %p",
            "%A, %B %d, %Y %H:%M",
            "%A, %B %d, %Y %I:%M %p",
            "%A, %b %d, %Y %H:%M",
            "%A, %b %d, %Y %I:%M %p",
        )

        @staticmethod
        def _strip_range(text: str) -> str:
            range_match = re.search(
                r"\b([A-Za-z]+)\s+(\d{1,2})\s*[-\u2013]\s*\d{1,2},\s*(\d{4})\b",
                text,
            )
            if range_match:
                return f"{range_match.group(1)} {range_match.group(2)}, {range_match.group(3)}"
            return text

        @staticmethod
        def _split_timezone(text: str, tzinfos: dict[str, int] | None) -> tuple[str, timezone | None]:
            if not tzinfos:
                return text, None
            match = re.search(r"\b([A-Z]{2,4})\b$", text)
            if not match:
                return text, None
            abbr = match.group(1)
            if abbr not in tzinfos:
                return text, None
            offset = tzinfos[abbr]
            tz = timezone(timedelta(seconds=offset))
            return text[: match.start()].strip(), tz

        @classmethod
        def parse(cls, value: str, tzinfos: dict[str, int] | None = None) -> datetime:
            text = re.sub(r"(\d)(st|nd|rd|th)\b", r"\1", value.strip(), flags=re.I)
            text = text.replace(" noon", " 12:00 PM").replace(" midnight", " 12:00 AM")
            text = re.sub(r"\bat\b", " ", text, flags=re.I)
            text = re.sub(r"\s+", " ", cls._strip_range(text)).strip(" ,")

            tz_text, fallback_tz = cls._split_timezone(text, tzinfos)

            iso_candidate = tz_text.replace("Z", "+00:00")
            try:
                parsed = datetime.fromisoformat(iso_candidate)
                if parsed.tzinfo is None and fallback_tz is not None:
                    parsed = parsed.replace(tzinfo=fallback_tz)
                return parsed
            except ValueError:
                pass

            try:
                parsed = parsedate_to_datetime(text)
                if parsed.tzinfo is None and fallback_tz is not None:
                    parsed = parsed.replace(tzinfo=fallback_tz)
                return parsed
            except (TypeError, ValueError, IndexError, OverflowError):
                pass

            for candidate in (tz_text, text):
                for fmt in cls._FORMATS:
                    try:
                        parsed = datetime.strptime(candidate, fmt)
                        if parsed.tzinfo is None and fallback_tz is not None:
                            parsed = parsed.replace(tzinfo=fallback_tz)
                        return parsed
                    except ValueError:
                        continue

            raise ValueError(f"Unsupported date format: {value}")

    date_parser = _FallbackDateParser()


ROOT = Path(__file__).resolve().parent
SOURCES_PATH = ROOT / "sources.json"
OUTPUT_DIR = ROOT / "output"
EVENTS_JSON = OUTPUT_DIR / "events.json"
SOURCE_DEBUG_JSON = OUTPUT_DIR / "source_debug.json"
SOURCE_REPORT_HTML = OUTPUT_DIR / "source_report.html"
EVENTS_CSV = OUTPUT_DIR / "events.csv"
PRIORITY_CSV = OUTPUT_DIR / "priority_events.csv"
EVENTS_ICS = OUTPUT_DIR / "zcyber_security_events.ics"
EVENTS_HTML = OUTPUT_DIR / "index.html"

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
NOW = datetime.now(timezone.utc)
LOOKBACK_DAYS = 7
LOOKAHEAD_DAYS = 370
TZINFOS = {
    "ET": -4 * 3600,
    "EDT": -4 * 3600,
    "EST": -5 * 3600,
    "CT": -5 * 3600,
    "CDT": -5 * 3600,
    "CST": -6 * 3600,
    "MT": -6 * 3600,
    "MDT": -6 * 3600,
    "MST": -7 * 3600,
    "PT": -7 * 3600,
    "PDT": -7 * 3600,
    "PST": -8 * 3600,
}


@dataclass
class Event:
    title: str
    start: datetime
    date_key: str = ""
    end: datetime | None = None
    url: str = ""
    source: str = ""
    location: str = ""
    description: str = ""
    region: str = ""
    focus: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    priority_score: int = 0
    city: str = "other-us"
    topic: str = "broad"

    def key(self) -> str:
        raw = "|".join(
            [
                normalize(self.title),
                self.start.date().isoformat(),
                normalize(self.location),
            ]
        )
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]

    def as_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "start": self.start.isoformat(),
            "date_key": self.date_key or self.start.date().isoformat(),
            "end": self.end.isoformat() if self.end else "",
            "url": self.url,
            "source": self.source,
            "location": self.location,
            "description": self.description,
            "region": self.region,
            "focus": self.focus,
            "tags": self.tags,
            "priority_score": self.priority_score,
            "city": self.city,
            "topic": self.topic,
        }


def normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.lower()).strip()


def fetch(url: str) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,text/calendar,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Upgrade-Insecure-Requests": "1",
        },
    )
    with urllib.request.urlopen(req, timeout=12) as response:
        raw = response.read()
        charset = response.headers.get_content_charset() or "utf-8"
        return raw.decode(charset, errors="replace")


def load_sources() -> dict[str, Any]:
    return json.loads(SOURCES_PATH.read_text())


def flatten_jsonld(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, list):
        for item in value:
            found.extend(flatten_jsonld(item))
    elif isinstance(value, dict):
        if value.get("@type") == "Event":
            found.append(value)
        item = value.get("item")
        if isinstance(item, dict) and item.get("@type") == "Event":
            found.append(item)
        for child in value.values():
            if isinstance(child, (dict, list)):
                found.extend(flatten_jsonld(child))
    return found


def parse_jsonld_events(page: str) -> list[dict[str, Any]]:
    blocks = re.findall(
        r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
        page,
        flags=re.I | re.S,
    )
    events: list[dict[str, Any]] = []
    for block in blocks:
        cleaned = html.unescape(block).strip()
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            continue
        events.extend(flatten_jsonld(data))
    return events


def parse_next_data_events(page: str) -> list[dict[str, Any]]:
    """Fallback for Luma/Next pages where events are embedded in __NEXT_DATA__."""
    match = re.search(
        r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>',
        page,
        flags=re.S,
    )
    if not match:
        return []
    try:
        data = json.loads(html.unescape(match.group(1)))
    except json.JSONDecodeError:
        return []

    events: list[dict[str, Any]] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            event_obj = obj.get("event")
            if isinstance(event_obj, dict) and event_obj.get("name") and event_obj.get("start_at"):
                url_slug = event_obj.get("url", "")
                events.append(
                    {
                        "@type": "Event",
                        "name": event_obj.get("name", ""),
                        "startDate": event_obj.get("start_at", ""),
                        "endDate": event_obj.get("end_at", ""),
                        "url": f"https://luma.com/{url_slug}" if url_slug else "",
                        "location": obj.get("geo_address_info") or "",
                        "description": obj.get("calendar", {}).get("description_short", ""),
                    }
                )
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for value in obj:
                walk(value)

    walk(data)
    return events


def absolute_url(base_url: str, href: str) -> str:
    if not href:
        return base_url
    return urllib.parse.urljoin(base_url, html.unescape(href))


def strip_tags(value: str) -> str:
    value = re.sub(r"<script.*?</script>", "", value, flags=re.I | re.S)
    value = re.sub(r"<style.*?</style>", "", value, flags=re.I | re.S)
    value = re.sub(r"<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", html.unescape(value)).strip()


def normalize_datetime_text(value: str) -> str:
    text = html.unescape(str(value)).replace("·", " ").replace("@", " ")
    text = re.sub(
        r"\bfrom\s+([0-9]{1,2}:[0-9]{2}(?:\s*[AP]M)?)\s+to\s+[0-9]{1,2}:[0-9]{2}(?:\s*[AP]M)?\s*\(?([A-Z]{2,4})\)?",
        r"\1 \2",
        text,
        flags=re.I,
    )
    text = re.sub(r"\bto\s+[0-9]{1,2}:[0-9]{2}(?:\s*[AP]M)?\s*\(?[A-Z]{2,4}\)?", "", text, flags=re.I)
    text = re.sub(r"\(([A-Z]{2,4})\)", r" \1 ", text)
    return re.sub(r"\s+", " ", text).strip()


def clean_isaca_title(value: str) -> str:
    title = re.sub(r"^\d+\s+(?:to|of)\s+\d+.*?\bAll\b\s+", "", value).strip()
    title = re.sub(r"^[A-Za-z ]+ Chapter\s+", "", title).strip()
    title = re.sub(r"^(?:[A-Z][a-z]+\s+\d{4}\s+)+", "", title).strip()
    return title


def parse_eastbay_events(page: str, base_url: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    blocks = re.findall(r"<article\b[^>]*>(.*?)</article>", page, flags=re.I | re.S)
    for block in blocks:
        title_match = re.search(r"<h3\b[^>]*>.*?<a\b[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>.*?</h3>", block, flags=re.I | re.S)
        if not title_match:
            continue
        title = strip_tags(title_match.group(2))
        url = absolute_url(base_url, title_match.group(1))

        date_match = re.search(r"📅\s*([^<]+)", block)
        location_match = re.search(r"📍\s*([^<]+)", block)
        source_match = re.search(r"via\s+([^<]+)", block, flags=re.I)
        kind_match = re.search(r'<div class="[^"]*uppercase[^"]*"[^>]*>(.*?)</div>', block, flags=re.I | re.S)

        date_text = strip_tags(date_match.group(1)) if date_match else ""
        location = strip_tags(location_match.group(1)) if location_match else "Bay Area, CA, US"
        source_name = strip_tags(source_match.group(1)) if source_match else "East Bay Cyber"
        kind = strip_tags(kind_match.group(1)) if kind_match else "Event"

        events.append(
            {
                "@type": "Event",
                "name": title,
                "startDate": date_text,
                "endDate": "",
                "url": url,
                "location": location,
                "description": f"{kind} via {source_name}",
            }
        )
    return events


def parse_first_events(page: str, base_url: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    pattern = re.compile(r"<li\b[^>]*class=[\"'][^\"']*event-wrapper[^\"']*[\"'][^>]*>.*?</li>", re.I | re.S)
    attr_pattern = re.compile(r'\b(data-[a-z-]+|title)=[\"\']([^\"\']*)[\"\']', re.I)
    for match in pattern.finditer(page):
        block = match.group(0)
        attrs = {name.lower(): html.unescape(value) for name, value in attr_pattern.findall(block)}
        if not attrs.get("data-start"):
            continue

        url_match = re.search(r"<a\b[^>]*class=[\"'][^\"']*p-url[^\"']*[\"'][^>]*href=[\"']([^\"']+)[\"']", block, flags=re.I)
        url = absolute_url(base_url, url_match.group(1)) if url_match else base_url
        title = attrs.get("data-event") or attrs.get("title") or strip_tags(block)
        country = attrs.get("data-country", "")
        city = attrs.get("data-city", "")
        event_type = attrs.get("data-type", "FIRST Event")
        location = ", ".join([part for part in [city, country] if part])
        events.append(
            {
                "@type": "Event",
                "name": title,
                "startDate": attrs.get("data-start", ""),
                "endDate": attrs.get("data-end", ""),
                "url": url,
                "location": location,
                "description": event_type,
            }
        )
    return events


def parse_meetup_group_events(page: str, base_url: str) -> list[dict[str, Any]]:
    lowered = page.lower()
    start = lowered.find("upcoming events")
    if start == -1:
        return []
    end_candidates = [lowered.find(marker, start + 1) for marker in ["past events", "group links", "organizers", "members"]]
    end_candidates = [idx for idx in end_candidates if idx != -1]
    end = min(end_candidates) if end_candidates else len(page)
    section = page[start:end]

    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in re.finditer(r"<a\b[^>]*href=[\"']([^\"']*/events/[^\"']+)[\"'][^>]*>(.*?)</a>", section, flags=re.I | re.S):
        url = absolute_url(base_url, match.group(1))
        text = strip_tags(match.group(2))
        if not text:
            continue
        date_match = re.search(
            r"(?P<date>(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+[A-Z][a-z]{2}\s+\d{1,2}(?:,\s+\d{4})?\s*[·-]\s*\d{1,2}:\d{2}\s*[AP]M\s+[A-Z]{2,4})",
            text,
        )
        if not date_match:
            continue
        title = text[: date_match.start()].strip(" -·")
        remainder = text[date_match.end() :].strip(" -·")
        remainder = re.sub(r"\s+\d+\s+attendees.*$", "", remainder).strip()
        if not title:
            continue
        key = f"{title}|{date_match.group('date')}"
        if key in seen:
            continue
        seen.add(key)
        events.append(
            {
                "@type": "Event",
                "name": title,
                "startDate": date_match.group("date").replace("·", " "),
                "endDate": "",
                "url": url,
                "location": remainder or "",
                "description": "",
            }
        )
    if events:
        return events

    text = strip_tags(section)
    for match in re.finditer(
        r"(?P<title>.+?)\s+(?P<date>(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+[A-Z][a-z]{2}\s+\d{1,2}(?:,\s+\d{4})?\s*[·-]\s*\d{1,2}:\d{2}\s*[AP]M\s+[A-Z]{2,4})\s+(?P<location>.*?)(?:\s+\d+\s+attendees|$)",
        text,
        flags=re.S,
    ):
        title = re.sub(r"^(Upcoming events|See all)\s*", "", match.group("title")).strip(" -·")
        if not title or len(title) < 6:
            continue
        key = f"{title}|{match.group('date')}"
        if key in seen:
            continue
        seen.add(key)
        events.append(
            {
                "@type": "Event",
                "name": title,
                "startDate": match.group("date").replace("·", " "),
                "endDate": "",
                "url": base_url,
                "location": match.group("location").strip(" -·"),
                "description": "",
            }
        )
    return events


def parse_owasp_chapter_events(page: str, base_url: str) -> list[dict[str, Any]]:
    text = strip_tags(page)
    events: list[dict[str, Any]] = []

    detailed = re.search(
        r"Upcoming Event\(s\)\s*Date\s*&\s*Time:\s*(?P<start>.*?)\s*Topic:\s*(?P<title>.*?)\s*Location:\s*(?P<location>.*?)\s*Organizers:\s*(?P<organizers>.*?)\s*Registration Link:",
        text,
        flags=re.I | re.S,
    )
    if detailed:
        url_match = re.search(r'href=[\"\']([^\"\']*meetup[^\"\']*)[\"\']', page, flags=re.I)
        start_text = detailed.group("start").replace("@", "").replace("Central", "").strip()
        events.append(
            {
                "@type": "Event",
                "name": detailed.group("title").strip(),
                "startDate": start_text,
                "endDate": "",
                "url": absolute_url(base_url, url_match.group(1)) if url_match else base_url,
                "location": detailed.group("location").strip(),
                "description": detailed.group("organizers").strip(),
            }
        )
        return events

    upcoming_section = re.search(r"Upcoming Events\s*(?P<body>.*?)(?:Past Events|Participation|Watch|Star)", text, flags=re.I | re.S)
    if not upcoming_section:
        return []
    body = upcoming_section.group("body")
    for match in re.finditer(r"[“\"]?(?P<title>[^”\"\n]+)[”\"]?\s*(?P<url>https?://www\.meetup\.com/[^\s]+)?", body):
        title = match.group("title").strip(" -·")
        if not title or len(title) < 8:
            continue
        if "owasp" not in normalize(title) and "cyber" not in normalize(title) and "security" not in normalize(title):
            continue
        url = match.group("url") or base_url
        events.append(
            {
                "@type": "Event",
                "name": title,
                "startDate": "",
                "endDate": "",
                "url": url,
                "location": "",
                "description": "",
            }
        )
        break
    return events


def parse_isaca_calendar_events(page: str, base_url: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in re.finditer(r"<a\b[^>]*href=[\"']([^\"']*CalendarEventKey[^\"']*)[\"'][^>]*>(.*?)</a>", page, flags=re.I | re.S):
        url = absolute_url(base_url, match.group(1))
        title = clean_isaca_title(strip_tags(match.group(2)))
        if not title or title in seen:
            continue
        if len(title) < 6 or "Chapter Events List" in title or "Contact" in title:
            continue
        context = strip_tags(page[match.end() : match.end() + 1200])
        if "Community:" not in context:
            continue

        start_text = ""
        end_text = ""
        location = ""
        when_match = re.search(r"When:\s*(.*?)\s*Community:", context, flags=re.S)
        if when_match:
            start_text = when_match.group(1).strip()
        else:
            span_match = re.search(r"Starts:\s*(.*?)\s*Ends:\s*(.*?)\s*Community:", context, flags=re.S)
            if span_match:
                start_text = span_match.group(1).strip()
                end_text = span_match.group(2).strip()
        where_match = re.search(r"Where:\s*(.*?)\s*Community:", context, flags=re.S)
        if where_match:
            location = where_match.group(1).strip()
        if not start_text:
            continue
        seen.add(title)
        events.append(
            {
                "@type": "Event",
                "name": title,
                "startDate": start_text,
                "endDate": end_text,
                "url": url,
                "location": location,
                "description": "ISACA chapter event",
            }
        )
    if events:
        return events

    text = strip_tags(page)
    start_idx = text.find("1 to ")
    if start_idx != -1:
        text = text[start_idx:]
    pattern = re.compile(
        r"(?P<title>[A-Z0-9\[\(].{5,140}?)\s+"
        r"(?:(?:When:\s*(?P<when>.*?))|(?:Starts:\s*(?P<starts>.*?)(?:\s*Ends:\s*(?P<ends>.*?))?))"
        r"(?:\s*Where:\s*(?P<where>.*?))?\s*Community:\s*(?P<community>.*?)(?="
        r"(?:[A-Z0-9\[\(].{5,140}?\s+(?:When:|Starts:))|Contact Us|Membership|$)",
        flags=re.S,
    )
    for match in pattern.finditer(text):
        title = clean_isaca_title(match.group("title").strip(" -·"))
        if not title or "Chapter Events List" in title or "Use the" in title:
            continue
        start_text = (match.group("when") or match.group("starts") or "").strip()
        if not start_text:
            continue
        events.append(
            {
                "@type": "Event",
                "name": title,
                "startDate": start_text,
                "endDate": (match.group("ends") or "").strip(),
                "url": base_url,
                "location": (match.group("where") or "").strip(),
                "description": f"ISACA {match.group('community').strip()}",
            }
        )
    return events


def parse_csa_atl_events(page: str, base_url: str) -> list[dict[str, Any]]:
    text = strip_tags(page)
    match = re.search(
        r"Upcoming Events\s*(?P<date>[A-Z][a-z]+\s+\d{1,2},\s+\d{4})\s*(?P<title>.*?)\s*(?P<location>.*?)(?:Join CSA Atlanta|Get event invites|Subscribe|Sponsors & Partners)",
        text,
        flags=re.S,
    )
    if not match:
        return []
    return [
        {
            "@type": "Event",
            "name": match.group("title").strip(),
            "startDate": match.group("date").strip(),
            "endDate": "",
            "url": base_url,
            "location": match.group("location").strip(),
            "description": "CSA Atlanta chapter event",
        }
    ]


def parse_configured_event(source: dict[str, Any]) -> list[dict[str, Any]]:
    event = source.get("event", {})
    if not event:
        return []
    return [
        {
            "@type": "Event",
            "name": event.get("title", source.get("name", "")),
            "startDate": event.get("start", ""),
            "endDate": event.get("end", ""),
            "url": source.get("url", ""),
            "location": event.get("location", ""),
            "description": event.get("description", ""),
        }
    ]


def parse_cra_events(page: str, base_url: str) -> list[dict[str, Any]]:
    text = strip_tags(page)
    month = r"Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
    prefixes = (
        "Cybersecurity Summit",
        "CyberRisk CISO Dinner",
        "CyberRisk Leadership Exchange",
        "Virtual Summit",
        "Hot Topic Webcast",
        "CISO Stories",
        "Identiverse",
        "InfoSec World",
        "MSSP Alert Live",
    )
    prefix_pattern = "|".join(re.escape(prefix) for prefix in prefixes)
    pattern = re.compile(
        rf"(?P<title>(?:{prefix_pattern}).{{0,140}}?)\s+"
        rf"(?P<date>(?:{month})\s+\d{{1,2}}\s*,?\s*20\d{{2}})\s+"
        r"(?P<format>In-Person|Virtual)",
        flags=re.I | re.S,
    )

    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in pattern.finditer(text):
        title = re.sub(r"\s+", " ", match.group("title")).strip(" -·,")
        title = re.sub(r"^(CRA Events\s+View All Events\s*)+", "", title).strip()
        key = f"{title}|{match.group('date')}"
        if key in seen:
            continue
        seen.add(key)
        location = "Online"
        if match.group("format").lower() == "in-person":
            location_match = re.search(r":\s*([^:]+)$", title)
            location = f"{location_match.group(1).strip()}, US" if location_match else "US"
        events.append(
            {
                "@type": "Event",
                "name": title,
                "startDate": match.group("date"),
                "endDate": "",
                "url": base_url,
                "location": location,
                "description": f"CyberRisk Alliance {match.group('format')} event",
            }
        )
    return events


def parse_evanta_calendar(page: str, base_url: str) -> list[dict[str, Any]]:
    text = strip_tags(page)
    month = r"Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
    target_cities = {
        "atlanta",
        "chicago",
        "new york",
        "san francisco",
        "boston",
        "dallas",
        "denver",
        "detroit",
        "houston",
        "minneapolis",
        "ohio",
        "seattle",
        "southern california",
        "washington, dc",
        "florida",
        "global",
    }
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for marker in re.finditer(r"CISO\s+Community\s+(Executive\s+Summit|Inner\s+Circle|Town\s+Hall)", text, flags=re.I):
        prefix = text[max(0, marker.start() - 120) : marker.start()]
        date_match = list(re.finditer(rf"(?P<day>\d{{1,2}})(?:-\d{{1,2}})?\s+(?P<month>{month})(?:\s+(?:{month})\s+20\d{{2}})?", prefix, flags=re.I))
        if not date_match:
            continue
        date = date_match[-1]
        city_text = prefix[date.end() :].strip()
        city_text = re.sub(r"^[A-Z][a-z]{2,9}\s+20\d{2}\s+", "", city_text, flags=re.I)
        location = re.sub(r"^(?:[a-z-]+\s+)+", "", city_text, flags=re.I).strip()
        location = re.sub(r"^20\d{2}\s+", "", location).strip()
        location = re.sub(r"\s+", " ", location)
        if normalize(location) not in target_cities:
            continue
        event_kind = re.sub(r"\s+", " ", marker.group(0)).strip()
        title = f"{location} {event_kind}"
        key = f"{date.group('day')}|{date.group('month')}|{title}"
        if key in seen:
            continue
        seen.add(key)
        if location == "Global":
            location = "US"
        events.append(
            {
                "@type": "Event",
                "name": title,
                "startDate": f"{date.group('month')} {date.group('day')}, {NOW.year}",
                "endDate": "",
                "url": base_url,
                "location": f"{location}, US",
                "description": "Evanta Gartner CISO community event",
            }
        )
    return events


def parse_health_isac_summits(page: str, base_url: str) -> list[dict[str, Any]]:
    text = strip_tags(page)
    pattern = re.compile(
        r"(?P<title>20\d{2}\s+(?:Spring|Fall)\s+Americas Summit)\s+"
        r"(?P<start>[A-Z][a-z]+\s+\d{1,2})\s*[-–]\s*(?P<end>(?:[A-Z][a-z]+\s+)?\d{1,2},\s*20\d{2})\s+"
        r"(?P<location>[A-Za-z ,.-]+?,\s*[A-Z]{2},\s*USA)",
        flags=re.S,
    )
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in pattern.finditer(text):
        title = match.group("title").strip()
        if title in seen:
            continue
        seen.add(title)
        start = match.group("start")
        end = match.group("end")
        if not re.match(r"[A-Z][a-z]+", end):
            end = f"{start.split()[0]} {end}"
        events.append(
            {
                "@type": "Event",
                "name": f"Health-ISAC {title}",
                "startDate": f"{start}, {NOW.year}",
                "endDate": end,
                "url": base_url,
                "location": match.group("location").strip(),
                "description": "Health-ISAC Americas summit",
            }
        )
    return events


def parse_tag_events(page: str, base_url: str) -> list[dict[str, Any]]:
    """Technology Association of Georgia (GrowthZone) calendar. Pairs each
    schema.org startDate with its nearest preceding event title link."""
    metas = list(re.finditer(r'itemprop="startDate" content="([^"]+)"', page))
    ends = list(re.finditer(r'itemprop="endDate" content="([^"]+)"', page))
    titles = list(
        re.finditer(
            r'href="(https://members\.tagonline\.org/calendar/Details/[^"]+)"[^>]*>\s*([A-Z][^<]{4,140}?)\s*</a>',
            page,
        )
    )
    events: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for mt in metas:
        prev = [t for t in titles if t.end() <= mt.start()]
        if not prev:
            continue
        t = prev[-1]
        name = html.unescape(t.group(2).strip())
        start = mt.group(1).strip()
        if (name, start) in seen:
            continue
        seen.add((name, start))
        end = next((e.group(1).strip() for e in ends if e.start() > mt.start()), "")
        events.append(
            {
                "@type": "Event",
                "name": name,
                "startDate": start,
                "endDate": end,
                "url": t.group(1),
                "location": "Atlanta, GA, US",
                "description": "Technology Association of Georgia event",
            }
        )
    return events


def parse_secureworld_events(page: str, base_url: str) -> list[dict[str, Any]]:
    """SecureWorld /events listing: regional conferences with start/end dates and venues."""
    events: list[dict[str, Any]] = []
    for blk in re.split(r'<div class="event upcoming', page)[1:]:
        blk = blk[:1500]
        title_m = re.search(r"<h2>\s*([^<]+?)\s*</h2>", blk)
        start_m = re.search(r'class="start-date">\s*(\d{4}-\d{2}-\d{2})', blk)
        if not title_m or not start_m:
            continue
        end_m = re.search(r'class="end-date">\s*(\d{4}-\d{2}-\d{2})', blk)
        venue_m = re.search(r'class="venue-name">\s*([^<]+?)\s*</div>', blk, flags=re.S)
        url_m = re.search(r'href="(https://events\.secureworld\.io/details/[^"]+)"', blk)
        title = html.unescape(title_m.group(1).strip())
        venue = html.unescape(venue_m.group(1).strip()) if venue_m else ""
        location = f"{venue}, {title}" if venue else title
        events.append(
            {
                "@type": "Event",
                "name": f"SecureWorld {title}",
                "startDate": start_m.group(1),
                "endDate": end_m.group(1) if end_m else "",
                "url": url_m.group(1) if url_m else base_url,
                "location": location,
                "description": "SecureWorld regional cybersecurity conference",
            }
        )
    return events


def parse_cra_upcoming_events(page: str, base_url: str) -> list[dict[str, Any]]:
    """CyberRisk Alliance upcoming-events (Webflow CMS list): CISO Dinners,
    Leadership Exchanges, and Cybersecurity Summits across US cities."""
    events: list[dict[str, Any]] = []
    for blk in page.split('role="listitem" class="upcoming-event-list_item')[1:]:
        blk = blk[:4000]
        name_m = re.search(r'fs-cmsfilter-field="name"[^>]*>\s*(.*?)\s*</h2>', blk, flags=re.S)
        date_m = re.search(r'class="text-size-medium">\s*([A-Za-z]{3,9}\.?\s+\d{1,2},\s+\d{4})', blk)
        if not name_m or not date_m:
            continue
        name = re.sub(r"<[^>]+>", "", name_m.group(1)).strip()
        if not name:
            continue
        locs = re.findall(r'fs-cmsfilter-field="locations"[^>]*>\s*([^<]+?)\s*<', blk)
        location = next(
            (loc.strip() for loc in locs if loc.strip().lower() not in ("in-person", "virtual", "in person")),
            "",
        )
        fmt_m = re.search(r'fs-cmsfilter-field="format"[^>]*>\s*([^<]+?)\s*<', blk)
        fmt = fmt_m.group(1).strip() if fmt_m else "Event"
        events.append(
            {
                "@type": "Event",
                "name": name,
                "startDate": date_m.group(1),
                "endDate": "",
                "url": base_url,
                "location": location or "United States",
                "description": f"CyberRisk Alliance {fmt}",
            }
        )
    return events


def _ics_unfold(text: str) -> str:
    # RFC 5545 line folding: a CRLF (or LF) followed by a space or tab continues the previous line.
    return re.sub(r"\r?\n[ \t]", "", text)


def _ics_unescape(value: str) -> str:
    return (
        value.replace("\\n", " ")
        .replace("\\N", " ")
        .replace("\\,", ",")
        .replace("\\;", ";")
        .replace("\\\\", "\\")
        .strip()
    )


def _ics_datetime_to_iso(value: str) -> str:
    value = value.strip()
    match = re.match(r"^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})(Z)?)?", value)
    if not match:
        return value
    year, month, day, hour, minute, second, zulu = match.groups()
    if hour is None:
        return f"{year}-{month}-{day}"
    iso = f"{year}-{month}-{day}T{hour}:{minute}:{second}"
    return iso + "+00:00" if zulu else iso


def parse_ics_events(page: str, base_url: str) -> list[dict[str, Any]]:
    """Parse VEVENTs from an iCalendar (.ics) feed, e.g. a public Google Calendar.

    One ICS feed (such as a community-maintained city calendar) often aggregates
    every local chapter (ISACA, ISSA, ISC2, OWASP, CSA, InfraGard, BSides), so this
    is the highest-leverage way to cover local chapter events.
    """
    text = _ics_unfold(page)
    events: list[dict[str, Any]] = []
    for block in re.findall(r"BEGIN:VEVENT(.*?)END:VEVENT", text, flags=re.S):
        props: dict[str, str] = {}
        for line in block.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            name, _, val = line.partition(":")
            key = name.split(";", 1)[0].upper()
            if key in ("SUMMARY", "LOCATION", "DESCRIPTION", "URL"):
                props[key] = _ics_unescape(val)
            elif key in ("DTSTART", "DTEND"):
                props[key] = _ics_datetime_to_iso(val)
        title = props.get("SUMMARY", "").strip()
        start = props.get("DTSTART", "")
        if not title or not start:
            continue
        url = props.get("URL") or base_url
        if not props.get("URL"):
            link = re.search(r"https?://\S+", props.get("DESCRIPTION", ""))
            if link:
                url = link.group(0).rstrip(").,;")
        events.append(
            {
                "@type": "Event",
                "name": title,
                "startDate": start,
                "endDate": props.get("DTEND", ""),
                "url": url,
                "location": props.get("LOCATION", ""),
                "description": props.get("DESCRIPTION", ""),
            }
        )
    return events


def parse_raw_events(page: str, source: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    parser = source.get("parser", "auto")
    if parser == "configured_event":
        return parse_configured_event(source), "configured_event"
    if parser == "eastbay":
        return parse_eastbay_events(page, source["url"]), "eastbay"
    if parser == "first_microdata":
        return parse_first_events(page, source["url"]), "first_microdata"
    if parser == "meetup_group":
        return parse_meetup_group_events(page, source["url"]), "meetup_group"
    if parser == "owasp_chapter":
        return parse_owasp_chapter_events(page, source["url"]), "owasp_chapter"
    if parser == "isaca_calendar":
        return parse_isaca_calendar_events(page, source["url"]), "isaca_calendar"
    if parser == "csa_atl":
        return parse_csa_atl_events(page, source["url"]), "csa_atl"
    if parser == "cra_events":
        return parse_cra_events(page, source["url"]), "cra_events"
    if parser == "evanta_calendar":
        return parse_evanta_calendar(page, source["url"]), "evanta_calendar"
    if parser == "health_isac_summits":
        return parse_health_isac_summits(page, source["url"]), "health_isac_summits"
    if parser == "ics":
        return parse_ics_events(page, source["url"]), "ics"
    if parser == "cra_upcoming":
        return parse_cra_upcoming_events(page, source["url"]), "cra_upcoming"
    if parser == "secureworld":
        return parse_secureworld_events(page, source["url"]), "secureworld"
    if parser == "tag":
        return parse_tag_events(page, source["url"]), "tag"

    raw_events = parse_jsonld_events(page)
    if raw_events:
        return raw_events, "jsonld"
    raw_events = parse_next_data_events(page)
    if raw_events:
        return raw_events, "next_data"
    return [], "none"


def parse_event_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, list):
        value = value[0] if value else ""
    try:
        parsed = date_parser.parse(normalize_datetime_text(str(value)), tzinfos=TZINFOS)
    except (ValueError, TypeError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_event_date_key(value: Any, fallback: datetime) -> str:
    if isinstance(value, list):
        value = value[0] if value else ""
    try:
        parsed = date_parser.parse(normalize_datetime_text(str(value)), tzinfos=TZINFOS)
        return parsed.date().isoformat()
    except (ValueError, TypeError, OverflowError):
        return fallback.date().isoformat()


def stringify_location(value: Any) -> str:
    if not value:
        return ""
    if isinstance(value, str):
        return re.sub(r"\s+", " ", value).strip()
    if isinstance(value, list):
        return ", ".join(filter(None, [stringify_location(v) for v in value]))
    if isinstance(value, dict):
        if value.get("@type") == "VirtualLocation":
            return value.get("url", "Online")
        address = value.get("address", value)
        if isinstance(address, dict):
            parts = [
                address.get("streetAddress", ""),
                address.get("addressLocality", ""),
                address.get("addressRegion", ""),
                address.get("addressCountry", ""),
            ]
            result = ", ".join([str(p) for p in parts if p])
            if result:
                return result
        return value.get("name", "")
    return str(value)


def tags_for_event(text: str, include: list[str], priority: list[str]) -> tuple[list[str], int]:
    lower = normalize(text)
    tags = [kw for kw in include if kw.lower() in lower]
    score = len(tags)
    for kw in priority:
        if kw.lower() in lower:
            score += 3
    if "san francisco" in lower or "bay area" in lower or "moscone" in lower:
        score += 5
    if "healthcare" in lower or "hipaa" in lower:
        score += 4
    if "fintech" in lower or "financial services" in lower:
        score += 4
    return sorted(set(tags)), score


def matches_any_keyword(text: str, keywords: list[str]) -> bool:
    lower = normalize(text)
    for keyword in keywords:
        normalized = normalize(keyword)
        if not normalized:
            continue
        escaped = re.escape(normalized).replace(r"\ ", r"\s+")
        pattern = rf"(?<![a-z0-9]){escaped}(?![a-z0-9])"
        if re.search(pattern, lower):
            return True
    return False


def event_topic(title: str, description: str, location: str, focus: list[str], tags: list[str]) -> str:
    text = normalize(" ".join([title, description, location, " ".join(focus), " ".join(tags)]))
    if any(term in text for term in ["healthcare", "health", "hipaa", "medical", "hospital", "iomt", "himss"]):
        return "health"
    if any(term in text for term in ["fintech", "financial services", "bank", "banking", "payments", "finance"]):
        return "fintech"
    return "broad"


def event_city(title: str, description: str, location: str, region: str) -> str:
    text = normalize(" ".join([title, description, location, region]))
    if any(term in text for term in ["san francisco", "bay area", "silicon valley", "east bay", "moscone", "santa clara", "san jose", "oakland", "berkeley", "burlingame", "palo alto", "mountain view", "sunnyvale"]) or re.search(r"\bsf\b", text):
        return "sf"
    if any(term in text for term in ["new york", "nyc", "manhattan", "brooklyn"]):
        return "nyc"
    if "atlanta" in text:
        return "atlanta"
    if "chicago" in text:
        return "chicago"
    if any(term in text for term in ["nashville", "brentwood, tn", "franklin, tn", "murfreesboro", "middle tennessee"]):
        return "nashville"
    if any(term in text for term in ["orlando", "kissimmee", "winter park", "maitland", "lake mary", "altamonte", "central florida"]):
        return "orlando"
    if any(term in text for term in ["detroit", "novi, mi", "troy, mi", "southfield", "dearborn", "livonia", "warren, mi", "auburn hills", "ann arbor", "metro detroit"]):
        return "detroit"
    return "other-us"


def is_us_event(title: str, description: str, location: str, region: str) -> bool:
    text = normalize(" ".join([title, description, location, region]))
    foreign_markers = [
        "canada",
        "france",
        "singapore",
        "united kingdom",
        "great britain",
        "india",
        "germany",
        "denmark",
        "ireland",
        "ecuador",
        "belarus",
        "london",
        "mumbai",
        "bangalore",
        "copenhagen",
        "dublin",
        "quito",
        "minsk",
        "ottawa",
        "cannes",
    ]
    if any(marker in text for marker in foreign_markers):
        return False
    if re.search(r",\s*(gb|in|ie|dk|de|ec|sg|mx|nl)\b", text):
        return False
    if region in {"Bay Area", "US"}:
        return True
    if any(term in text for term in ["united states", ", us", " usa", "san francisco", "new york", "atlanta", "chicago", "berkeley", "santa clara", "bellevue", "washington", "california", "maryland", "minnesota", "texas", "virginia", "philadelphia", "san diego", "boston", "arlington", "nashville", "tennessee", "orlando", "florida", "detroit", "michigan", "novi", "kissimmee"]):
        return True
    return False


def raw_event_title(raw: dict[str, Any]) -> str:
    return re.sub(r"\s+", " ", str(raw.get("name", "")).strip())


def event_from_schema(raw: dict[str, Any], source: dict[str, Any], settings: dict[str, Any]) -> tuple[Event | None, str]:
    title = re.sub(r"\s+", " ", str(raw.get("name", "")).strip())
    start_raw = raw.get("startDate")
    start = parse_event_datetime(start_raw)
    if not title or not start:
        return None, "missing_title_or_date"
    date_key = parse_event_date_key(start_raw, start)

    end = parse_event_datetime(raw.get("endDate"))
    if end and end <= start:
        end = None

    url = raw.get("url") or raw.get("@id") or source.get("url", "")
    if isinstance(url, list):
        url = url[0] if url else ""
    location = stringify_location(raw.get("location"))
    description = re.sub(r"\s+", " ", str(raw.get("description", "")).strip())
    region = source.get("region", "")

    if not is_us_event(title, description, location, region):
        return None, "non_us"

    event_text = " ".join([title, description, location])
    source_text = " ".join([source.get("name", ""), " ".join(source.get("focus", []))])
    text = " ".join([event_text, source_text])
    keyword_text = event_text if source.get("require_any_keyword") else text
    include_keywords = settings["keywords"]["include"] + source.get("extra_include_keywords", [])
    priority_keywords = settings["keywords"]["priority"] + source.get("extra_priority_keywords", [])
    tags, score = tags_for_event(keyword_text, include_keywords, priority_keywords)
    keyword_gate = source.get("require_any_keyword", [])
    if keyword_gate and not matches_any_keyword(event_text, keyword_gate):
        return None, "missing_keyword"
    excludes = settings["keywords"].get("exclude", [])
    source_excludes = source.get("exclude_keywords", [])
    if any(ex.lower() in normalize(text) for ex in [*excludes, *source_excludes]):
        return None, "excluded_keyword"

    return Event(
        title=title,
        start=start,
        date_key=date_key,
        end=end,
        url=str(url),
        source=source.get("name", ""),
        location=location,
        description=description,
        region=region,
        focus=source.get("focus", []),
        tags=tags,
        priority_score=score,
        city=event_city(title, description, location, region + " " + " ".join(source.get("focus", []))),
        topic=event_topic(title, description, location, source.get("focus", []), tags),
    ), "accepted"


def in_window(event: Event) -> bool:
    return NOW - timedelta(days=LOOKBACK_DAYS) <= event.start <= NOW + timedelta(days=LOOKAHEAD_DAYS)


def collect_events(settings: dict[str, Any]) -> tuple[list[Event], list[dict[str, str]], list[dict[str, Any]]]:
    events: list[Event] = []
    errors: list[dict[str, str]] = []
    debug_rows: list[dict[str, Any]] = []
    total = len(settings["sources"])
    for idx, source in enumerate(settings["sources"], 1):
        debug = {
            "source": source["name"],
            "url": source["url"],
            "region": source.get("region", ""),
            "focus": source.get("focus", []),
            "status": "pending",
            "parser": "",
            "raw_events_found": 0,
            "accepted": 0,
            "rejected": {},
            "sample_raw_titles": [],
            "sample_accepted_titles": [],
        }
        print(f"[{idx}/{total}] {source['name']}", file=sys.stderr, flush=True)
        try:
            page = "" if source.get("parser") == "configured_event" else fetch(source["url"])
            raw_events, parser_name = parse_raw_events(page, source)
            debug["parser"] = parser_name
            debug["raw_events_found"] = len(raw_events)
            debug["sample_raw_titles"] = [raw_event_title(raw) for raw in raw_events[:8]]
            for raw in raw_events:
                event, reason = event_from_schema(raw, source, settings)
                if event and not in_window(event):
                    reason = "out_of_window"
                    event = None
                if event:
                    events.append(event)
                    debug["accepted"] += 1
                    if len(debug["sample_accepted_titles"]) < 8:
                        debug["sample_accepted_titles"].append(event.title)
                else:
                    debug["rejected"][reason] = debug["rejected"].get(reason, 0) + 1
            debug["status"] = "ok"
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            debug["status"] = "error"
            debug["error"] = str(exc)
            errors.append({"source": source["name"], "url": source["url"], "error": str(exc)})
        debug_rows.append(debug)

    by_key: dict[str, Event] = {}
    for event in events:
        key = event.key()
        existing = by_key.get(key)
        if not existing or event.priority_score > existing.priority_score:
            by_key[key] = event

    deduped = sorted(by_key.values(), key=lambda e: (e.start, -e.priority_score, e.title))
    return deduped, errors, debug_rows


def ics_escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace(";", "\\;")
        .replace(",", "\\,")
        .replace("\r", "")
        .replace("\n", "\\n")
    )


def ics_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def write_ics(events: list[Event]) -> None:
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Z Cyber GTM//Security Event Calendar//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        "X-WR-CALNAME:Z Cyber Security Event Radar",
        "X-WR-CALDESC:Cybersecurity, healthcare security, fintech security, and Bay Area security events.",
    ]
    generated = ics_datetime(NOW)
    for event in events:
        uid = f"{event.key()}@zcyber-gtm.local"
        end = event.end or event.start + timedelta(hours=2)
        description = " | ".join(
            filter(
                None,
                [
                    event.description,
                    f"Source: {event.source}",
                    f"Tags: {', '.join(event.tags)}" if event.tags else "",
                    event.url,
                ],
            )
        )
        lines.extend(
            [
                "BEGIN:VEVENT",
                f"UID:{uid}",
                f"DTSTAMP:{generated}",
                f"DTSTART:{ics_datetime(event.start)}",
                f"DTEND:{ics_datetime(end)}",
                f"SUMMARY:{ics_escape(event.title)}",
                f"DESCRIPTION:{ics_escape(description)}",
                f"LOCATION:{ics_escape(event.location)}",
                f"URL:{ics_escape(event.url)}",
                "END:VEVENT",
            ]
        )
    lines.append("END:VCALENDAR")
    EVENTS_ICS.write_text("\r\n".join(lines) + "\r\n")


def write_json(events: list[Event], errors: list[dict[str, str]]) -> None:
    payload = {
        "generated_at": NOW.isoformat(),
        "event_count": len(events),
        "events": [event.as_dict() for event in events],
        "source_errors": errors,
    }
    EVENTS_JSON.write_text(json.dumps(payload, indent=2))


def write_source_debug(debug_rows: list[dict[str, Any]]) -> None:
    SOURCE_DEBUG_JSON.write_text(json.dumps(debug_rows, indent=2))


def write_source_report(debug_rows: list[dict[str, Any]]) -> None:
    rows = []
    for row in debug_rows:
        rejected = ", ".join(f"{key}: {value}" for key, value in row.get("rejected", {}).items()) or ""
        samples = "<br>".join(html.escape(title) for title in row.get("sample_accepted_titles", [])[:5]) or "<span class=\"muted\">None</span>"
        rows.append(
            f"""
            <tr>
              <td><a href="{html.escape(row.get('url', ''))}">{html.escape(row.get('source', ''))}</a></td>
              <td>{html.escape(row.get('parser', ''))}</td>
              <td>{row.get('raw_events_found', 0)}</td>
              <td>{row.get('accepted', 0)}</td>
              <td>{html.escape(rejected)}</td>
              <td>{samples}</td>
            </tr>
            """
        )
    SOURCE_REPORT_HTML.write_text(
        textwrap.dedent(
            f"""\
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <title>Source Debug Report</title>
              <style>
                :root {{ --blue:#0156BB; --red:#DD3E3E; --cream:#FFFEFD; --ink:#1E1E1E; --line:#ECEEF1; }}
                body {{ margin:0; background:var(--cream); color:var(--ink); font-family:Arial,sans-serif; }}
                header {{ padding:36px 28px 18px; border-bottom:1px solid var(--line); }}
                h1 {{ margin:0 0 8px; font-family:Georgia,serif; font-size:44px; font-weight:400; }}
                a {{ color:var(--blue); text-decoration:none; }}
                a:hover {{ text-decoration:underline; }}
                main {{ padding:24px 28px; overflow-x:auto; }}
                table {{ width:100%; border-collapse:collapse; background:white; }}
                th, td {{ text-align:left; vertical-align:top; border-bottom:1px solid var(--line); padding:10px; font-size:14px; }}
                th {{ color:var(--blue); background:#f8fafc; }}
                .muted {{ color:#667085; }}
              </style>
            </head>
            <body>
              <header>
                <h1>Source Debug Report</h1>
                <p class="muted">Generated {html.escape(NOW.astimezone().strftime("%b %-d, %Y %-I:%M %p %Z"))}. Accepted counts are before cross-source deduping.</p>
                <p><a href="index.html">Back to calendar</a> · <a href="source_debug.json">Raw JSON</a></p>
              </header>
              <main>
                <table>
                  <thead>
                    <tr>
                      <th>Source</th>
                      <th>Parser</th>
                      <th>Raw</th>
                      <th>Accepted</th>
                      <th>Rejected</th>
                      <th>Accepted sample</th>
                    </tr>
                  </thead>
                  <tbody>{''.join(rows)}</tbody>
                </table>
              </main>
            </body>
            </html>
            """
        )
    )


def write_csv(events: list[Event]) -> None:
    def write(path: Path, rows: list[Event]) -> None:
        with path.open("w", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "start",
                    "title",
                    "source",
                    "region",
                    "location",
                    "tags",
                    "topic",
                    "city",
                    "priority_score",
                    "url",
                ],
            )
            writer.writeheader()
            for event in rows:
                writer.writerow(
                    {
                        "start": event.start.isoformat(),
                        "title": event.title,
                        "source": event.source,
                        "region": event.region,
                        "location": event.location,
                        "tags": ", ".join(event.tags),
                        "topic": event.topic,
                        "city": event.city,
                        "priority_score": event.priority_score,
                        "url": event.url,
                    }
                )

    write(EVENTS_CSV, events)
    priority_events = sorted(
        [event for event in events if event.priority_score >= 6 or event.region == "Bay Area"],
        key=lambda event: (-event.priority_score, event.start, event.title),
    )
    write(PRIORITY_CSV, priority_events)


def event_category(event: Event) -> str:
    text = normalize(" ".join([event.title, event.location, " ".join(event.tags), " ".join(event.focus)]))
    if event.region == "Bay Area" or any(term in text for term in ["san francisco", "bay area", "santa clara", "berkeley"]):
        return "bay-area"
    if any(term in text for term in ["healthcare", "health", "hipaa", "medical", "iomt", "himss"]):
        return "health"
    if any(term in text for term in ["fintech", "financial services", "bank", "banking", "finance"]):
        return "fintech"
    return "broad"


def write_html(events: list[Event], errors: list[dict[str, str]]) -> None:
    events_payload = json.dumps([event.as_dict() for event in events])
    error_note = ""
    if errors:
        error_note = f"<p class=\"errors\">{len(errors)} source(s) could not be fetched. See events.json for details.</p>"
    EVENTS_HTML.write_text(
        textwrap.dedent(
            f"""\
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <title>Z Cyber Security Event Radar</title>
              <style>
                :root {{
                  --blue: #0156BB;
                  --red: #DD3E3E;
                  --cream: #FFFEFD;
                  --ink: #1E1E1E;
                  --line: #ECEEF1;
                }}
                body {{
                  margin: 0;
                  background: var(--cream);
                  color: var(--ink);
                  font-family: Arial, sans-serif;
                }}
                header {{
                  padding: 42px 28px 24px;
                  border-bottom: 1px solid var(--line);
                }}
                h1 {{
                  margin: 0 0 8px;
                  font-family: Georgia, serif;
                  font-size: clamp(34px, 5vw, 64px);
                  font-weight: 400;
                  letter-spacing: 0;
                }}
                .sub {{
                  max-width: 760px;
                  color: #4b5563;
                  font-size: 18px;
                  line-height: 1.5;
                }}
                .topbar {{
                  display: flex;
                  gap: 16px;
                  align-items: flex-start;
                  justify-content: space-between;
                  flex-wrap: wrap;
                }}
                .actions {{
                  margin-top: 18px;
                  display: flex;
                  flex-wrap: wrap;
                  gap: 10px;
                }}
                .actions a {{
                  border: 1px solid var(--blue);
                  color: var(--blue);
                  padding: 9px 12px;
                  text-decoration: none;
                  font-weight: 700;
                }}
                .controls {{
                  display: flex;
                  gap: 12px;
                  flex-wrap: wrap;
                  align-items: center;
                  padding: 14px 28px;
                  border-bottom: 1px solid var(--line);
                  background: white;
                }}
                .month-controls {{
                  display: flex;
                  gap: 8px;
                  align-items: center;
                  margin-right: auto;
                }}
                .month-title {{
                  min-width: 190px;
                  color: var(--blue);
                  font-size: 22px;
                  font-weight: 800;
                }}
                button, select {{
                  border: 1px solid var(--line);
                  background: white;
                  color: var(--ink);
                  cursor: pointer;
                  font: inherit;
                  font-weight: 700;
                  padding: 8px 10px;
                }}
                button:hover, select:hover {{
                  border-color: var(--blue);
                }}
                main {{
                  max-width: 1240px;
                  margin: 0 auto;
                  padding: 28px;
                }}
                .calendar {{
                  display: grid;
                  grid-template-columns: repeat(7, minmax(0, 1fr));
                  border: 1px solid var(--line);
                  background: var(--line);
                  gap: 1px;
                }}
                .weekday {{
                  background: #f8fafc;
                  color: #5f6874;
                  font-weight: 700;
                  padding: 10px;
                  text-transform: uppercase;
                  font-size: 12px;
                  letter-spacing: 0.06em;
                }}
                .day {{
                  min-height: 145px;
                  background: var(--cream);
                  padding: 9px;
                  overflow: hidden;
                }}
                .day.other-month {{
                  background: #f7f7f6;
                  color: #9ca3af;
                }}
                .day-number {{
                  color: var(--ink);
                  font-weight: 800;
                  margin-bottom: 7px;
                }}
                .event-pill {{
                  display: block;
                  margin: 5px 0;
                  border-left: 3px solid var(--blue);
                  background: white;
                  color: var(--ink);
                  padding: 6px 7px;
                  text-decoration: none;
                  font-size: 12px;
                  line-height: 1.25;
                  box-shadow: 0 0 0 1px rgba(1, 86, 187, 0.08);
                }}
                .event-pill:hover {{
                  box-shadow: 0 0 0 1px var(--blue);
                  transform: translateY(-1px);
                }}
                .event-pill.health {{
                  border-left-color: var(--red);
                }}
                .event-pill.fintech {{
                  border-left-color: #1E1E1E;
                }}
                .event-pill .event-title {{
                  font-weight: 800;
                }}
                .event-pill .event-meta {{
                  color: #667085;
                  display: block;
                  margin-top: 2px;
                }}
                .event-pill .event-source {{
                  color: var(--blue);
                  display: block;
                  font-weight: 800;
                  margin-top: 4px;
                }}
                .errors {{
                  color: var(--red);
                  font-weight: 700;
                }}
                .empty-state {{
                  padding: 28px;
                  color: #667085;
                  border: 1px solid var(--line);
                  background: white;
                }}
                @media (max-width: 700px) {{
                  .calendar {{
                    grid-template-columns: 1fr;
                  }}
                  .weekday {{
                    display: none;
                  }}
                  .day {{
                    min-height: 110px;
                  }}
                }}
              </style>
            </head>
            <body>
              <header>
                <div class="topbar">
                  <div>
                    <h1>Z Cyber Security Event Radar</h1>
                    <p class="sub">US-based cybersecurity, healthcare security, fintech security, and security leadership events from free public sources. Generated {html.escape(NOW.astimezone().strftime("%b %-d, %Y %-I:%M %p %Z"))}.</p>
                  </div>
                  <div class="actions">
                    <a href="zcyber_security_events.ics">Subscribe/import .ics</a>
                    <a href="events.csv">Download CSV</a>
                    <a href="priority_events.csv">Priority CSV</a>
                    <a href="source_report.html">Source report</a>
                    <a href="events.json">View JSON</a>
                  </div>
                </div>
                {error_note}
              </header>
              <section class="controls" aria-label="Calendar controls">
                <div class="month-controls">
                  <button id="prevMonth" type="button">Prev</button>
                  <div class="month-title" id="monthTitle"></div>
                  <button id="nextMonth" type="button">Next</button>
                </div>
                <label>
                  Location
                  <select id="cityFilter">
                    <option value="all">All US</option>
                    <option value="sf">SF / Bay Area</option>
                    <option value="nyc">NYC</option>
                    <option value="atlanta">Atlanta</option>
                    <option value="chicago">Chicago</option>
                    <option value="nashville">Nashville</option>
                    <option value="orlando">Orlando</option>
                    <option value="detroit">Detroit</option>
                    <option value="other-us">Other US</option>
                  </select>
                </label>
                <label>
                  Topic
                  <select id="topicFilter">
                    <option value="all">All topics</option>
                    <option value="health">Health</option>
                    <option value="fintech">Fintech</option>
                    <option value="broad">Broad security</option>
                  </select>
                </label>
              </section>
              <main>
                <div class="calendar" id="calendar"></div>
                <p class="empty-state" id="emptyState" hidden>No events match these filters for this month.</p>
              </main>
              <script>
                const events = {events_payload};
                const calendar = document.getElementById("calendar");
                const emptyState = document.getElementById("emptyState");
                const monthTitle = document.getElementById("monthTitle");
                const cityFilter = document.getElementById("cityFilter");
                const topicFilter = document.getElementById("topicFilter");
                const monthNames = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
                const weekdays = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
                let visibleMonth = new Date("{NOW.date().isoformat()}T12:00:00");

                function filteredEvents() {{
                  return events.filter((event) => {{
                    const cityMatch = cityFilter.value === "all" || event.city === cityFilter.value;
                    const topicMatch = topicFilter.value === "all" || event.topic === topicFilter.value;
                    return cityMatch && topicMatch;
                  }});
                }}

                function eventDate(event) {{
                  return event.date_key || event.start.slice(0, 10);
                }}

                function escapeHtml(value) {{
                  return String(value || "").replace(/[&<>"']/g, (char) => ({{
                    "&": "&amp;",
                    "<": "&lt;",
                    ">": "&gt;",
                    '"': "&quot;",
                    "'": "&#39;",
                  }}[char]));
                }}

                function renderCalendar() {{
                  calendar.innerHTML = "";
                  weekdays.forEach((day) => {{
                    const node = document.createElement("div");
                    node.className = "weekday";
                    node.textContent = day;
                    calendar.appendChild(node);
                  }});

                  const year = visibleMonth.getFullYear();
                  const month = visibleMonth.getMonth();
                  monthTitle.textContent = `${{monthNames[month]}} ${{year}}`;

                  const first = new Date(year, month, 1);
                  const start = new Date(year, month, 1 - first.getDay());
                  const monthEvents = filteredEvents();
                  let visibleCount = 0;

                  for (let i = 0; i < 42; i += 1) {{
                    const date = new Date(start);
                    date.setDate(start.getDate() + i);
                    const dateKey = date.toISOString().slice(0, 10);
                    const day = document.createElement("div");
                    day.className = `day${{date.getMonth() === month ? "" : " other-month"}}`;

                    const number = document.createElement("div");
                    number.className = "day-number";
                    number.textContent = date.getDate();
                    day.appendChild(number);

                    monthEvents
                      .filter((event) => eventDate(event) === dateKey)
                      .sort((a, b) => b.priority_score - a.priority_score)
                      .forEach((event) => {{
                        visibleCount += 1;
                        const pill = document.createElement("a");
                        pill.className = `event-pill ${{event.topic}}`;
                        pill.href = event.url;
                        pill.target = "_blank";
                        pill.rel = "noopener noreferrer";
                        pill.title = `${{event.title}}\\n${{event.location || "Location TBD"}}`;
                        pill.innerHTML = `<span class="event-title">${{escapeHtml(event.title)}}</span><span class="event-meta">${{escapeHtml(event.city.replace("-", " "))}} · ${{escapeHtml(event.topic)}} · ${{escapeHtml(event.source)}}</span><span class="event-source">Open source -></span>`;
                        day.appendChild(pill);
                      }});

                    calendar.appendChild(day);
                  }}
                  emptyState.hidden = visibleCount > 0;
                }}

                document.getElementById("prevMonth").addEventListener("click", () => {{
                  visibleMonth = new Date(visibleMonth.getFullYear(), visibleMonth.getMonth() - 1, 1);
                  renderCalendar();
                }});
                document.getElementById("nextMonth").addEventListener("click", () => {{
                  visibleMonth = new Date(visibleMonth.getFullYear(), visibleMonth.getMonth() + 1, 1);
                  renderCalendar();
                }});
                cityFilter.addEventListener("change", renderCalendar);
                topicFilter.addEventListener("change", renderCalendar);
                renderCalendar();
              </script>
            </body>
            </html>
            """
        )
    )


def main() -> int:
    OUTPUT_DIR.mkdir(exist_ok=True)
    settings = load_sources()
    events, errors, debug_rows = collect_events(settings)
    write_json(events, errors)
    write_source_debug(debug_rows)
    write_source_report(debug_rows)
    write_csv(events)
    write_ics(events)
    write_html(events, errors)
    print(f"Wrote {len(events)} events")
    print(f"- {EVENTS_HTML}")
    print(f"- {EVENTS_ICS}")
    print(f"- {EVENTS_CSV}")
    if errors:
        print(f"Warning: {len(errors)} source errors; see events.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
