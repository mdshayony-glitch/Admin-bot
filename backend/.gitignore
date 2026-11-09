
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Bookmarklet Analysis Bot",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {
        "status": "online",
        "message": "Analysis Bot Backend is running"
    }

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.get("/indicators")
def indicators():
    return {
        "indicators": [
            "EMA", "SMA", "RSI", "MACD",
            "ADX", "ATR", "Bollinger Bands",
            "Stochastic", "CCI", "VWAP"
        ]
    }
