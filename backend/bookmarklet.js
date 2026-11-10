
(() => {
  const OLD = document.getElementById("bookmark-bot-widget");
  if (OLD) {
    OLD.remove();
    return;
  }

  const root = document.createElement("div");
  root.id = "bookmark-bot-widget";

  const shadow = root.attachShadow({ mode: "open" });

  shadow.innerHTML = `
    <style>
      * { box-sizing: border-box; }
      #logo {
        position: fixed;
        right: 18px;
        bottom: 90px;
        width: 58px;
        height: 58px;
        border-radius: 50%;
        background: #142b48;
        color: #65b8ff;
        border: 2px solid #65b8ff;
        display: grid;
        place-items: center;
        font-size: 25px;
        font-weight: bold;
        cursor: grab;
        z-index: 2147483647;
        box-shadow: 0 4px 18px #0009;
        user-select: none;
      }
      #panel {
        position: fixed;
        right: 12px;
        bottom: 160px;
        width: min(340px, calc(100vw - 24px));
        background: #101a2b;
        color: #eaf2ff;
        border: 1px solid #314866;
        border-radius: 14px;
        padding: 15px;
        font: 14px Arial, sans-serif;
        z-index: 2147483646;
        box-shadow: 0 8px 30px #000b;
        display: none;
      }
      .top {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 15px;
      }
      .brand { font-size: 16px; font-weight: bold; }
      button {
        background: #1c3554;
        color: white;
        border: 1px solid #456587;
        border-radius: 8px;
        padding: 10px;
        cursor: pointer;
        font-weight: bold;
      }
      button:active { opacity: .7; }
      .option {
        display: block;
        width: 100%;
        margin: 9px 0;
        text-align: left;
        padding: 13px;
      }
      .muted { color: #9db0c9; font-size: 12px; }
      #details {
        margin-top: 12px;
        padding: 12px;
        border-radius: 9px;
        background: #172840;
        line-height: 1.6;
      }
      #close { padding: 5px 9px; }
    </style>

    <div id="logo" title="Move Bookmark Bot">B</div>

    <section id="panel">
      <div class="top">
        <div class="brand">BOOKMARK BOT</div>
        <button id="close">×</button>
      </div>

      <div class="muted">SELECT ANALYSIS MODE</div>
      <button class="option" data-mode="auto">
        ◈ OPTION 1 — AUTO ANALYSIS
        <div class="muted">Market monitoring and chart study</div>
      </button>

      <button class="option" data-mode="manual">
        ◈ OPTION 2 — MANUAL ANALYSIS
        <div class="muted">Choose market and indicators</div>
      </button>

      <div id="details">
        Select an option to continue.
      </div>

      <div class="muted" style="margin-top:12px">
        Educational analysis only. No guaranteed predictions.
      </div>
    </section>
  `;

  document.documentElement.appendChild(root);

  const logo = shadow.getElementById("logo");
  const panel = shadow.getElementById("panel");
  const details = shadow.getElementById("details");

  logo.addEventListener("click", () => {
    panel.style.display =
      panel.style.display === "block" ? "none" : "block";
  });

  shadow.getElementById("close").addEventListener("click", () => {
    panel.style.display = "none";
  });

  shadow.querySelectorAll(".option").forEach(button => {
    button.addEventListener("click", () => {
      const mode = button.dataset.mode;

      details.innerHTML = `
        <strong>${mode === "auto" ? "AUTO ANALYSIS" : "MANUAL ANALYSIS"}</strong>
        <p class="muted">Choose a data category:</p>
        <button id="live">LIVE DATA</button>
        <button id="otc">OTC DATA</button>
        <p class="muted" id="status">
          OTC data requires an authorized data source.
        </p>
        <p class="muted">
          Historical chart study and illustrative scenarios only.
          Future candles cannot be known in advance.
        </p>
      `;

      const status = details.querySelector("#status");

      details.querySelector("#live").onclick = () => {
        status.textContent =
          "Live public market data can be connected in a later step.";
      };

      details.querySelector("#otc").onclick = () => {
        status.textContent =
          "OTC data is not connected. An authorized source is required.";
      };
    });
  });

  let dragging = false;
  let moved = false;
  let startX = 0;
  let startY = 0;
  let offsetX = 0;
  let offsetY = 0;

  logo.addEventListener("pointerdown", event => {
    dragging = true;
    moved = false;
    startX = event.clientX;
    startY = event.clientY;

    const rect = logo.getBoundingClientRect();
    offsetX = event.clientX - rect.left;
    offsetY = event.clientY - rect.top;

    logo.setPointerCapture(event.pointerId);
  });

  logo.addEventListener("pointermove", event => {
    if (!dragging) return;

    if (
      Math.abs(event.clientX - startX) > 5 ||
      Math.abs(event.clientY - startY) > 5
    ) {
      moved = true;
    }

    if (moved) {
      logo.style.left = Math.max(
        0,
        Math.min(window.innerWidth - 58, event.clientX - offsetX)
      ) + "px";

      logo.style.top = Math.max(
        0,
        Math.min(window.innerHeight - 58, event.clientY - offsetY)
      ) + "px";

      logo.style.right = "auto";
      logo.style.bottom = "auto";
    }
  });

  logo.addEventListener("pointerup", () => {
    dragging = false;
    if (moved) {
      logo.dataset.dragged = "yes";
      setTimeout(() => delete logo.dataset.dragged, 250);
    }
  });

  logo.addEventListener("click", event => {
    if (logo.dataset.dragged === "yes") {
      event.stopImmediatePropagation();
    }
  }, true);
})();
