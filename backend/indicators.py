
from math import sqrt


def sma(values, period=14):
    if len(values) < period:
        return None
    return sum(values[-period:]) / period


def ema(values, period=14):
    if len(values) < period:
        return None

    multiplier = 2 / (period + 1)
    result = sum(values[:period]) / period

    for value in values[period:]:
        result = (value * multiplier) + (
            result * (1 - multiplier)
        )

    return result


def rsi(values, period=14):
    if len(values) <= period:
        return None

    changes = [
        values[i] - values[i - 1]
        for i in range(1, len(values))
    ]

    gains = [max(x, 0) for x in changes]
    losses = [max(-x, 0) for x in changes]

    avg_gain = sum(gains[:period]) / period
    avg_loss = sum(losses[:period]) / period

    for i in range(period, len(gains)):
        avg_gain = (
            avg_gain * (period - 1) + gains[i]
        ) / period
        avg_loss = (
            avg_loss * (period - 1) + losses[i]
        ) / period

    if avg_loss == 0:
        return 100.0

    rs = avg_gain / avg_loss
    return 100 - (100 / (1 + rs))


def bollinger_bands(values, period=20):
    if len(values) < period:
        return None

    recent = values[-period:]
    middle = sum(recent) / period

    variance = sum(
        (x - middle) ** 2 for x in recent
    ) / period

    deviation = sqrt(variance)

    return {
        "upper": middle + 2 * deviation,
        "middle": middle,
        "lower": middle - 2 * deviation
    }


def analyze(values):
    return {
        "sma_14": sma(values, 14),
        "ema_14": ema(values, 14),
        "rsi_14": rsi(values, 14),
        "bollinger_20": bollinger_bands(values, 20)
    }
