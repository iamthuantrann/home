import csv
import datetime
import pytz
import requests
import urllib
import uuid

from flask import redirect, render_template, request, session, url_for
from functools import wraps


import requests

def apology(message, code=400, redirect_url=None, button_text=None):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"), ("%", "~p"), ("#", "~h"), ("/", "~s"), ('"', "''")]:
            s = s.replace(old, new)
        return s

    # Function to fetch meme URL based on error message (dummy example)
    def get_meme_url(error_message):
        # Replace with actual meme API or predefined mapping
        meme_urls = {
            "must provide username": "https://example.com/meme1.jpg",
            "must provide password": "https://example.com/meme2.jpg",
            "username already exists": "https://example.com/meme3.jpg",
            # Add more mappings as needed
        }
        return meme_urls.get(error_message, "https://example.com/default_meme.jpg")  # Default meme URL

    meme_url = get_meme_url(message)  # Fetch meme URL based on error message

    return render_template("apology.html", top=code, bottom=escape(message), meme_url=meme_url, redirect_url=redirect_url, button_text=button_text), code

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


def lookup(symbol):
    """Look up quote for symbol."""

    # Prepare API request
    symbol = symbol.upper()
    end = datetime.datetime.now(pytz.timezone("US/Eastern"))
    start = end - datetime.timedelta(days=7)

    # Yahoo Finance API
    url = (
        f"https://query1.finance.yahoo.com/v7/finance/download/{urllib.parse.quote_plus(symbol)}"
        f"?period1={int(start.timestamp())}"
        f"&period2={int(end.timestamp())}"
        f"&interval=1d&events=history&includeAdjustedClose=true"
    )

    # Query API
    try:
        response = requests.get(
            url,
            cookies={"session": str(uuid.uuid4())},
            headers={"Accept": "*/*", "User-Agent": request.headers.get("User-Agent")},
        )
        response.raise_for_status()

        # CSV header: Date,Open,High,Low,Close,Adj Close,Volume
        quotes = list(csv.DictReader(response.content.decode("utf-8").splitlines()))
        price = round(float(quotes[-1]["Adj Close"]), 2)
        return {"price": price, "symbol": symbol}
    except (KeyError, IndexError, requests.RequestException, ValueError):
        return None


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"
