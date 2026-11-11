
import json
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from collections import defaultdict

BINANCE_API = "https://api.binance.com"

SUPPORTED_INTERVALS = {
    "1m": "1m",
    "2m": "2m",
    "3m": "3m",
    "5m": "5m",
    "15m": "15m",
    "30m": "30m",
    "1h": "1h",
    "4h": "4h",
    "1d": "1d",
}

DEFAULT_SYMBOLS = [
    "BTCUSDT", "ETHUSDT", "BNBUSDT",
    "SOLUSDT", "XRPUSDT", "DOGEUSDT",
    "ADAUSDT", "TRXUSDT", "LINKUSDT",
    "AVAXUSDT"
]


def _get_json(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "MarketAI/1.0"}
    )
    with urllib.request.urlopen(request, timeout=12) as response:
        return json.loads(response.read().decode("utf-8"))


def get_symbols():
    url = BINANCE_API + "/api/v3/exchangeInfo"
    data = _get_json(url)

    symbols = []
    for item in data.get("symbols", []):
        if (
            item.get("status") == "TRADING"
            and item.get("quoteAsset") == "USDT"
            and item.get("isSpotTradingAllowed", True)
        ):
            symbols.append(item["symbol"])

    return sorted(symbols)


def _get_raw_candles(symbol, interval, limit):
    params = urllib.parse.urlencode({
        "symbol": symbol.upper(),
        "interval": interval,
        "limit": min(max(int(limit), 10), 1000)
    })

    url = BINANCE_API + "/api/v3/klines?" + params
    rows = _get_json(url)

    candles = []
    for row in rows:
        candles.append({
            "time": int(row[0]),
            "open": float(row[1]),
            "high": float(row[2]),
            "low": float(row[3]),
            "close": float(row[4]),
            "volume": float(row[5]),
            "close_time": int(row[6]),
            "source": "Binance Spot"
        })

    return candles


def _make_two_minute_candles(one_minute):
    groups = defaultdict(list)

    for candle in one_minute:
        bucket = candle["time"] // 120000
        groups[bucket].append(candle)

    result = []

    for bucket in sorted(groups):
        items = groups[bucket]

        if len(items) != 2:
            continue

        result.append({
            "time": items[0]["time"],
            "open": items[0]["open"],
            "high": max(x["high"] for x in items),
            "low": min(x["low"] for x in items),
            "close": items[-1]["close"],
            "volume": sum(x["volume"] for x in items),
            "close_time": items[-1]["close_time"],
            "source": "Binance Spot (2m aggregated)"
        })

    return result


def get_candles(symbol="BTCUSDT", interval="1m", limit=200):
    symbol = symbol.upper().strip()

    if not symbol.isalnum():
        raise ValueError("Invalid market symbol")

    if interval not in SUPPORTED_INTERVALS:
        raise ValueError("Unsupported timeframe")

    if interval == "2m":
        raw = _get_raw_candles(symbol, "1m", min(limit * 2 + 4, 1000))
        candles = _make_two_minute_candles(raw)
        return candles[-limit:]

    return _get_raw_candles(
        symbol,
        SUPPORTED_INTERVALS[interval],
        limit
    )


def market_status():
    return {
        "provider": "Binance",
        "market": "Crypto Spot",
        "connected": True,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "available_timeframes": list(SUPPORTED_INTERVALS.keys()),
        "note": "Live exchange data; not Quotex OTC data."
    }
