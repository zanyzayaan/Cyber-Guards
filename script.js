
    /************************************************************************
     * CyberGuardians — single-file demo app
     * - Replace the brand logo by setting the image src below (logoUrl variable)
     * - All data is stored in localStorage under "cg_data" (safe demo, no server)
     *
     * Features implemented:
     * - heuristics-based leak scoring for email, phone, links, messages
     * - sensitivity detection using token/keyword checks
     * - suggestions tailored to risk level
     * - alert saving, dashboard counters, and news panel (static)
     *
     * This is a client-side demo. For production:
     * - Move scoring to server or vetted local model
     * - Integrate threat intel feeds & link reputation services
     * - Add authentication & secure storage
     ************************************************************************/

    // ---------- CONFIG ----------
    const logoUrl = ""; // <-- PLACE YOUR LOGO URL HERE (string). If blank, fallback icon shows.

    // sample static news (replace by server/RSS later)
    const NEWS = [
      {title: "Massive SMS phishing campaign targets bank customers", date: "2025-11-10", summary: "Fake transaction alerts sent via SMS with malicious links. Don’t click suspicious links; verify directly with your bank."},
      {title: "New credential stuffing technique spreads via leaked lists", date: "2025-11-08", summary: "Attackers re-use credentials from old breaches to compromise accounts. Use unique passwords and MFA."},
      {title: "Fraudsters target customers with fake refund portals", date: "2025-11-05", summary: "Always verify refund links by visiting the official website, not through email or SMS links."},
      {title: "SIM swap scams rise in urban centers", date: "2025-10-29", summary: "Call your carrier to add a SIM PIN and avoid sharing OTPs with anyone."}
    ];

    // ---------- Storage & state ----------
    const STORAGE_KEY = "cg_data_v1";
    const defaultState = {checks:[], alerts:[], stats:{total:0,low:0,medium:0,high:0}, last:null};

    function loadState(){
      try{
        const raw = localStorage.getItem(STORAGE_KEY);
        return raw ? JSON.parse(raw) : JSON.parse(JSON.stringify(defaultState));
      }catch(e){ console.warn("load error",e); return JSON.parse(JSON.stringify(defaultState)); }
    }
    function saveState(s){ localStorage.setItem(STORAGE_KEY, JSON.stringify(s)); }

    let state = loadState();

    // ---------- Logo handling ----------
    (function initLogo(){
      const img = document.getElementById("brandLogo");
      const fallback = document.getElementById("logoFallback");
      if(logoUrl && logoUrl.trim().length>0){
        img.src = logoUrl;
        img.onload = ()=>{ img.style.display="block"; fallback.style.display="none"; };
        img.onerror = ()=>{ img.style.display="none"; fallback.style.display="block"; };
      } else {
        img.style.display="none"; fallback.style.display="block";
      }
    })();

    // ---------- Navigation ----------
    function navTo(e){
      const target = e.currentTarget.dataset.target;
      document.querySelectorAll(".nav-item").forEach(n=> n.classList.toggle("active", n.dataset.target===target));
      document.querySelectorAll(".view").forEach(v=> v.style.display = "none");
      const el = document.getElementById("view-" + target);
      if(el) el.style.display = "block";
      // adjust URL hash for shareability
      history.replaceState(null,'', '#'+target);
      renderSidebarHighlights();
    }

    // set initial view based on hash
    (function startView(){
      const hash = location.hash.replace('#','') || 'dashboard';
      const el = document.querySelector(`.nav-item[data-target="${hash}"]`);
      if(el) el.click(); else document.querySelector(`.nav-item[data-target="dashboard"]`).click();
      renderAll();
    })();

    // ---------- Analysis logic (heuristic) ----------
    function analyzeInput(){
      const raw = document.getElementById("inputText").value.trim();
      if(!raw){
        alert("Please paste some text (email, link, SMS, or phone number) to analyze.");
        return;
      }
      const selectedType = document.getElementById("inputType").value;
      document.getElementById("processing").textContent = "Analyzing...";
      setTimeout(()=>{ // small simulated processing
        const result = scoreText(raw, selectedType);
        showResult(result);
        saveCheck(result);
        document.getElementById("processing").textContent = "";
      }, 250);
    }

    // Quick analyze for small input
    function runQuickCheck(){
      const quick = document.getElementById("quickInput").value.trim();
      if(!quick) { alert("Enter something in quick input."); return; }
      document.getElementById("inputText").value = quick;
      document.getElementById("inputType").value = "auto";
      document.querySelector('.nav-item[data-target="check"]').click();
      analyzeInput();
    }

    // scoring heuristics - simple but reasonable for demo
    function scoreText(text, forcedType="auto"){
      const lowered = text.toLowerCase();
      const tokens = text.split(/\s+/).filter(Boolean);
      let score = 8; // base
      let reasons = [];

      // detect email
      const emailRegex = /[a-zA-Z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i;
      const email = text.match(emailRegex);

      // phone detection (various formats)
      const phoneRegex = /(\+?\d{1,3})?[\s-]?\(?\d{2,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}/;
      const phone = text.match(phoneRegex);

      // URL
      const urlRegex = /(https?:\/\/)?(www\.)?[a-z0-9\-]+\.[a-z]{2,}(\/\S*)?/i;
      const url = text.match(urlRegex);

      // credit card (simple)
      const ccRegex = /(?:\d[ -]*?){13,19}/;
      const cc = text.match(ccRegex);

      // sensitive keywords
      const sensitiveKeywords = ["password","pass","pwd","ssn","social security","cvv","credit card","card number","pin","otp","one-time","bank account","account number","routing"];
      const foundKeywords = sensitiveKeywords.filter(k => lowered.includes(k));

      // personal name heuristics - capitalized words (very rough)
      const capitalized = tokens.filter(t => /^[A-Z][a-z]{1,}/.test(t));

      // heuristics accumulate score
      if(email){ score += 28; reasons.push("Detected email address"); }
      if(phone && phone[0].replace(/\D/g,"").length >= 7){ score += 20; reasons.push("Detected phone number"); }
      if(url){ score += 22; reasons.push("Detected URL"); }
      if(cc){ score += 30; reasons.push("Possible credit-card-like number"); }

      if(foundKeywords.length){
        score += Math.min(40, foundKeywords.length * 18);
        reasons.push("Sensitive keywords: " + foundKeywords.join(", "));
      }

      if(capitalized.length >= 2 && text.length < 80){
        score += 8; reasons.push("Likely named person (capitalized tokens)");
      }

      // length & entropy-ish heuristic (long dumps of data -> higher risk)
      if(text.length > 120) { score += 10; reasons.push("Long text (more data)"); }

      // penalty for low-risk obvious cases
      if(!email && !phone && !url && foundKeywords.length===0 && !cc){
        // small positive check: if contains generic safe words
        score = Math.max(3, score - 5);
        reasons.push("No obvious contact or sensitive tokens detected");
      }

      // clamp 0-100
      score = Math.max(0, Math.min(100, Math.round(score)));

      // determine type
      let detectedType = forcedType === "auto" ? detectType(text) : forcedType;

      // sensitivity label
      let label = "Low", color = "var(--success)";
      if(score > 60){ label = "High"; color = "var(--danger)"; }
      else if(score > 30){ label = "Medium"; color = "var(--warn)"; }

      // generate suggestions
      const suggestions = generateSuggestions({score, label, email, phone, url, cc, foundKeywords, capitalized});

      // meta
      const now = new Date().toISOString();
      return {timestamp:now, raw:text, score, label, color, reasons, suggestions, detectedType};
    }

    function detectType(text){
      if(/[a-zA-Z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.test(text)) return "email";
      if(/https?:\/\/|www\./i.test(text)) return "link";
      if(/(?:\+?\d{1,3})?[\s-]?\(?\d{2,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}/.test(text)) return "phone";
      if(text.length < 200) return "sms";
      return "other";
    }

    function generateSuggestions({score,label,email,phone,url,cc,foundKeywords,capitalized}){
      const out = [];
      if(label === "High"){
        out.push("Do not share this information publicly.");
        out.push("If this is your data, change passwords and enable MFA where possible.");
        out.push("Contact the service provider if you believe credentials were leaked.");
      } else if(label === "Medium"){
        out.push("Avoid posting this in public forums; limit to trusted recipients.");
        out.push("Consider masking or redacting sensitive parts (e.g., last 4 digits only).");
      } else {
        out.push("Information appears low risk — still exercise caution before sharing.");
        out.push("Do not share passwords, OTP, or full card details with anyone.");
      }

      if(email) out.push("Email detected: consider using a disposable or secondary email for public forms.");
      if(phone) out.push("Phone number detected: avoid sharing with unknown contacts; enable carrier protections.");
      if(url) out.push("URL detected: do not click shortened or suspicious links; verify domain carefully.");
      if(cc) out.push("Possible card number detected: contact your issuer and monitor statements; do not send full card details.");
      if(foundKeywords.length) out.push("Contains sensitive keywords: redact or remove before sharing.");

      // unique suggestions trimming duplicates
      return Array.from(new Set(out));
    }

    // ---------- UI: show results ----------
    function showResult(result){
      document.getElementById("resultBox").style.display = "block";
      document.getElementById("scoreValue").textContent = result.score;
      document.getElementById("scoreMeta").textContent = `Type: ${result.detectedType} • Detected: ${result.reasons.join("; ") || "—"}`;
      const pill = document.getElementById("riskPill");
      pill.textContent = result.label;
      if(result.label === "High"){ pill.style.background = "var(--danger)"; }
      else if(result.label === "Medium"){ pill.style.background = "var(--warn)"; pill.style.color="#222"; }
      else { pill.style.background = "var(--success)"; }
      document.getElementById("riskBar").style.width = result.score + "%";

      // suggestions list
      const sug = document.getElementById("suggestions");
      sug.innerHTML = "";
      result.suggestions.forEach(s => {
        const d = document.createElement("div");
        d.className = "chip";
        d.textContent = "• " + s;
        sug.appendChild(d);
      });

      // cache the lastResult for quick actions
      window._lastResult = result;

      // update sidebar & peek
      state.last = result;
      renderAll();
    }

    // ---------- Persistence: save checks & alerts ----------
    function saveCheck(result){
      state.checks.unshift(result); // newest first
      state.stats.total = state.checks.length;
      // update stat buckets
      const low = state.checks.filter(c => c.label === "Low").length;
      const med = state.checks.filter(c => c.label === "Medium").length;
      const high = state.checks.filter(c => c.label === "High").length;
      state.stats.low = low; state.stats.medium = med; state.stats.high = high;
      state.last = result;
      saveState(state);
      renderAll();
    }

    function addToAlerts(){
      const r = window._lastResult;
      if(!r) { alert("No result to save as alert. Run an analysis first."); return; }
      // basic dedupe by timestamp or raw
      state.alerts.unshift(Object.assign({id:Date.now()}, r));
      saveState(state);
      renderAll();
      alert("Alert saved.");
    }

    function clearAlerts(){
      if(!confirm("Clear all saved alerts?")) return;
      state.alerts = [];
      saveState(state);
      renderAll();
    }

    function clearHistory(){
      if(!confirm("Clear all check history and stats?")) return;
      state = JSON.parse(JSON.stringify(defaultState));
      saveState(state);
      renderAll();
    }

    function exportAlerts(){
      const data = JSON.stringify(state.alerts, null, 2);
      const blob = new Blob([data], {type:"application/json"});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = "cyberguardians_alerts.json";
      a.click();
      URL.revokeObjectURL(url);
    }

    // ---------- UI helpers ----------
    function renderAll(){
      // stats
      document.getElementById("stat-total").textContent = state.stats.total || 0;
      document.getElementById("stat-high").textContent = state.stats.high || 0;
      document.getElementById("stat-medium").textContent = state.stats.medium || 0;
      document.getElementById("stat-low").textContent = state.stats.low || 0;

      // last check
      document.getElementById("lastCheck").textContent = state.last ? (state.last.score + " — " + state.last.label + " • " + (new Date(state.last.timestamp)).toLocaleString()) : "No checks run yet.";
      document.getElementById("sidebar-last").textContent = state.last ? new Date(state.last.timestamp).toLocaleString() : "—";
      document.getElementById("sidebar-top").textContent = (() => {
        if(state.alerts.length) return state.alerts[0].label + " (" + state.alerts[0].score + ")";
        if(state.last) return state.last.label + " ("+ state.last.score +")";
        return "—";
      })();

      // recent alerts peek
      const peek = document.getElementById("alertPeek");
      peek.innerHTML = "";
      if(state.alerts.length === 0){
        peek.innerHTML = '<div class="muted">No alerts yet. High risk checks will appear here.</div>';
      } else {
        state.alerts.slice(0,4).forEach(a => {
          const el = document.createElement("div");
          el.className = "alert-item";
          el.innerHTML = `<div>
                            <div style="font-weight:700">${a.label} • ${a.score}</div>
                            <div class="meta">${truncate(a.raw,60)}</div>
                          </div>
                          <div style="text-align:right">
                            <div class="meta">${new Date(a.timestamp).toLocaleString()}</div>
                          </div>`;
          peek.appendChild(el);
        });
      }

      // alerts full list
      const alertsFull = document.getElementById("alertsFull");
      alertsFull.innerHTML = "";
      if(state.alerts.length===0) alertsFull.innerHTML = '<div class="muted">No saved alerts.</div>';
      else state.alerts.forEach(a=>{
        const el = document.createElement("div");
        el.className = "alert-item";
        el.innerHTML = `<div>
                          <div style="font-weight:700">${a.label} • ${a.score}</div>
                          <div class="meta">${truncate(a.raw,140)}</div>
                        </div>
                        <div style="text-align:right">
                          <div class="meta">${new Date(a.timestamp).toLocaleString()}</div>
                          <div style="margin-top:6px">
                            <button class="btn ghost" onclick='removeAlert(${a.id})'>Remove</button>
                          </div>
                        </div>`;
        alertsFull.appendChild(el);
      });

      // sidebar alerts (short)
      const sidebarAlerts = document.getElementById("sidebarAlerts");
      sidebarAlerts.innerHTML = "";
      (state.alerts.slice(0,6)).forEach(a=>{
        const el = document.createElement("div");
        el.className = "alert-item";
        el.innerHTML = `<div style="font-weight:700">${a.label} • ${a.score}</div>
                        <div class="meta">${new Date(a.timestamp).toLocaleString()}</div>`;
        sidebarAlerts.appendChild(el);
      });
      if(state.alerts.length===0) sidebarAlerts.innerHTML = '<div class="muted">No alerts</div>';

      // news lists
      renderNews();

      // counters
      renderSidebarHighlights();
    }

    function removeAlert(id){
      if(!confirm("Remove this alert?")) return;
      state.alerts = state.alerts.filter(a=> a.id !== id);
      saveState(state);
      renderAll();
    }

    function truncate(s, n=60){ return s.length > n ? s.slice(0,n-1) + "…" : s; }

    // ---------- News rendering ----------
    function renderNews(){
      const newsList = document.getElementById("newsList");
      const sidebarNews = document.getElementById("sidebarNews");
      newsList.innerHTML = "";
      sidebarNews.innerHTML = "";

      NEWS.forEach(n=>{
        const el = document.createElement("div");
        el.className = "news-item";
        el.innerHTML = `<h4>${n.title}</h4><p class="muted">${n.date} • ${n.summary}</p>`;
        newsList.appendChild(el);

        const s = document.createElement("div");
        s.className = "news-item";
        s.style.padding = "8px";
        s.innerHTML = `<div style="font-weight:700;font-size:13px">${n.title}</div><div class="muted" style="font-size:12px">${n.date}</div>`;
        sidebarNews.appendChild(s);
      });
    }

    function refreshNews(){ renderNews(); alert("News refreshed (static demo)."); }
    function markAllRead(){ alert("All items marked read (demo)."); }

    // ---------- Utilities ----------
    function saveSample(){
      const sample = "john.doe@example.com\nPassword: Secret123\nhttps://suspicious.example/login?token=xyz\nCard: 4111 1111 1111 1111";
      document.getElementById("inputText").value = sample;
      document.getElementById("inputType").value = "auto";
    }

    function copyReport(){
      const r = window._lastResult;
      if(!r){ alert("No report to copy."); return; }
      const txt = `CyberGuardians report\nScore: ${r.score} (${r.label})\nDetected: ${r.reasons.join("; ")}\nSuggestions:\n- ${r.suggestions.join("\n- ")}\n\nRaw: ${r.raw}`;
      navigator.clipboard?.writeText(txt).then(()=> alert("Report copied to clipboard."), ()=> alert("Copy failed."));
    }

    function removeAllChildren(el){ while(el.firstChild) el.removeChild(el.firstChild); }

    // small UI highlight rendering (updates nav counts if needed)
    function renderSidebarHighlights(){
      // we could add badges or visual hints here in future
    }

    // allow quick removing via global
    window.removeAlert = removeAlert;

    // initial render
    renderAll();

    // accessibility: allow Enter key on quick input
    document.getElementById("quickInput").addEventListener("keydown", function(e){
      if(e.key === "Enter") { e.preventDefault(); runQuickCheck(); }
    });

    // Expose some functions for console debugging (dev)
    window.CG = {
      state, saveState, scoreText, analyzeInput, addToAlerts, exportAlerts
    };
  