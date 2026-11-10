
import os
import requests

BINANCE_API = "https://api.binance.com/api/v3/klines"


def get_candles(symbol="BTCUSDT", interval="1m", limit=100):
    allowed_intervals = {
        "1m", "5m", "15m", "30m", "1h", "4h", "1d"
    }

    if interval not in allowed_intervals:
        raise ValueError("Unsupported interval")

    if not 1 <= limit <= 500:
        raise ValueError("Limit must be between 1 and 500")

    response = requests.get(
        BINANCE_API,
        params={
            "symbol": symbol.upper(),
            "interval": interval,
            "limit": limit
        },
        timeout=15
    )
    response.raise_for_status()

    rows = response.json()

    return [
        {
            "time": row[0],
            "open": float(row[1]),
            "high": float(row[2]),
            "low": float(row[3]),
            "close": float(row[4]),
            "volume": float(row[5]),
            "closed": row[6] < int(
                __import__("time").time() * 1000
            )
        }
        for row in rows
    ]


def get_market_status():
    return {
        "provider": "Binance Public API",
        "available": True,
        "note": "Public crypto market data only. "
                "This is not Quotex or OTC price data."
    }
