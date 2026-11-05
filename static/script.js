const SAMPLES = [
  "URGENT: Your SBI account will be blocked today. Verify KYC immediately at http://sbi-kyc-update.example/login and share the OTP.",
  "Congratulations! You won a Rs 25,00,000 lottery. Pay the processing fee to claim@okaxis and call +91 98765 43210.",
  "Your parcel is held at customs. Pay Rs 49 delivery fee: www.parcel-track.example/pay. Account 123456789012, IFSC HDFC0001234.",
  "आपका खाता आज बंद हो जाएगा। तुरंत ओटीपी भेजें।",
  "Hi, are we still meeting for lunch tomorrow?"
];

const $ = (id) => document.getElementById(id);
let sessionId = null;

function addBubble(kind, text) {
  const div = document.createElement("div");
  div.className = "msg " + kind;
  const who = document.createElement("span");
  who.className = "who";
  who.textContent = kind === "scammer" ? "Incoming message" : "Agent (simulated victim)";
  const body = document.createElement("span");
  body.textContent = text;           // textContent: never inject HTML
  div.append(who, body);
  const log = $("log");
  const hint = log.querySelector(".hint");
  if (hint) hint.remove();
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

const LABELS = {
  upi_ids: "UPI IDs", phone_numbers: "Phone numbers", bank_accounts: "Bank accounts",
  ifsc_codes: "IFSC codes", phishing_links: "Links (not opened)"
};

function renderIntel(intel) {
  const box = $("intel");
  box.replaceChildren();
  let any = false;
  for (const key of Object.keys(LABELS)) {
    const vals = (intel && intel[key]) || [];
    if (!vals.length) continue;
    any = true;
    const g = document.createElement("div");
    g.className = "intel-group";
    const b = document.createElement("b");
    b.textContent = LABELS[key];
    g.appendChild(b);
    vals.forEach((v) => {
      const c = document.createElement("span");
      c.className = "chip";
      c.textContent = v;
      g.appendChild(c);
    });
    box.appendChild(g);
  }
  if (!any) {
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = "Nothing extracted yet.";
    box.appendChild(p);
  }
}

function renderResult(d) {
  const s = d.risk_score;
  $("score").textContent = s;
  $("type").textContent = d.scam_type || "—";
  $("explain").textContent = d.explanation || "";
  const bar = $("bar");
  bar.style.width = s + "%";
  bar.style.background = s >= 70 ? "var(--danger)" : s >= 40 ? "var(--warn)" : "var(--accent)";
  const ul = $("indicators");
  ul.replaceChildren();
  (d.indicators || []).forEach((i) => {
    const li = document.createElement("li");
    li.textContent = i;
    ul.appendChild(li);
  });
  renderIntel(d.extracted_intelligence);
}

async function send() {
  const text = $("msg").value.trim();
  if (!text) return;
  $("error").textContent = "";
  $("sendBtn").disabled = true;
  addBubble("scammer", text);
  $("msg").value = "";
  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: text, session_id: sessionId })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(typeof err.detail === "string" ? err.detail : "Request failed (" + res.status + ")");
    }
    const d = await res.json();
    sessionId = d.session_id;
    renderResult(d);
    $("reportBtn").disabled = false;
    if (d.agent_reply) addBubble("agent", d.agent_reply);
    else addBubble("agent", "(No scam detected, so the agent stays silent.)");
  } catch (e) {
    $("error").textContent = e.message;
  } finally {
    $("sendBtn").disabled = false;
  }
}

function newSession() {
  sessionId = null;
  $("log").replaceChildren();
  const p = document.createElement("p");
  p.className = "hint";
  p.textContent = "New session started. Paste a suspicious message below.";
  $("log").appendChild(p);
  renderResult({ risk_score: 0, scam_type: "—", indicators: [], explanation: "", extracted_intelligence: {} });
  $("reportBtn").disabled = true;
  $("error").textContent = "";
}

async function loadMode() {
  try {
    const d = await (await fetch("/api/status")).json();
    $("mode").textContent = d.label;
  } catch { $("mode").textContent = "Status unavailable"; }
}

document.addEventListener("DOMContentLoaded", () => {
  const sel = $("samples");
  SAMPLES.forEach((t, i) => {
    const o = document.createElement("option");
    o.value = i;
    o.textContent = t.slice(0, 60) + (t.length > 60 ? "…" : "");
    sel.appendChild(o);
  });
  sel.addEventListener("change", () => {
    if (sel.value !== "") $("msg").value = SAMPLES[Number(sel.value)];
    sel.value = "";
  });
  $("sendBtn").addEventListener("click", send);
  $("newBtn").addEventListener("click", newSession);
  $("reportBtn").addEventListener("click", () => {
    if (sessionId) window.location.href = "/api/report/" + encodeURIComponent(sessionId);
  });
  $("msg").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) send();
  });
  loadMode();
});
