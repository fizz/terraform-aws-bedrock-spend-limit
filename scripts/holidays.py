# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx>=0.27"]
# ///
"""Write a country's public holidays as JSON, for the module's holidays input.

monthly_budget_usd divides the budget by the month's business days, and these dates
are not business days. Observed days count: a holiday on a weekend moves to a weekday.
Data comes from holidaydb (https://holidaydb.com), which needs an API key.

Usage: HOLIDAYDB_API_KEY=... uv run scripts/holidays.py OUT.json [--country US] [YEAR ...]
Years default to this year and next. Run it again each year, then plan and apply.

    holidays = [for h in jsondecode(file("${path.module}/holidays.json")) : h.date]
"""

import argparse
import datetime as dt
import json
import os
import sys
import time
from pathlib import Path

import httpx

URL = "https://api.holidaydb.com/api/holidays"


def fetch(country):
    """One request, retried at most twice, and only when the server says to wait."""
    headers = {
        "Authorization": "Bearer " + os.environ["HOLIDAYDB_API_KEY"],
        "User-Agent": "terraform-aws-bedrock-spend-limit-holidays/1.0",
    }
    with httpx.Client(headers=headers, timeout=30) as client:
        for attempt in range(3):
            r = client.get(URL, params={"country": country})
            if r.status_code not in (429, 503) or attempt == 2:
                r.raise_for_status()
                return r.json()
            wait = int(r.headers.get("Retry-After", "30"))
            print(f"holidaydb answered {r.status_code}; waiting {wait}s as asked", file=sys.stderr)
            time.sleep(wait)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out", type=Path, help="JSON file to write")
    ap.add_argument("--country", default="US", help="ISO 3166-1 alpha-2 code (default US)")
    ap.add_argument("years", nargs="*", type=int, help="years to include (default this year and next)")
    args = ap.parse_args()

    this_year = dt.date.today().year
    years = set(args.years) or {this_year, this_year + 1}
    holidays = sorted(
        (
            {"date": h["start_date"], "name": h["summary"] + (" (observed)" if h["substitute"] else "")}
            for h in fetch(args.country)
            if h["type"] == "public_holiday" and h["scope"] == "national" and int(h["start_date"][:4]) in years
        ),
        key=lambda h: h["date"],
    )
    if not holidays:
        sys.exit(f"holidaydb returned no national public holidays for {args.country} in {sorted(years)}")
    args.out.write_text(json.dumps(holidays, indent=2) + "\n")
    print(f"{args.out}: {len(holidays)} holidays for {args.country} in {sorted(years)}")


if __name__ == "__main__":
    main()
