import { api, guard, getUsr, clrAuth, toast, fmtDate, riskBadge, roleBadge, statusBadge, loadingRow } from "./utils.js";
if (!guard("super_admin")) throw 0;
const usr = getUsr();
document.getElementById("sb-uname").textContent = usr.name || usr.email.split("@")[0];

// ── NAV ────────────────────────────────────────────────────────────────────
document.querySelectorAll(".nav-item[data-s]").forEach(n => {
  n.addEventListener("click", () => {
    document.querySelectorAll(".nav-item[data-s]").forEach(x => x.classList.remove("active"));
    document.querySelectorAll(".sec").forEach(x => x.classList.remove("active"));
    n.classList.add("active");
    const sec = document.getElementById("s-" + n.dataset.s);
    if (sec) sec.classList.add("active");
    load(n.dataset.s);
  });
});

function load(name) {
  if (name === "overview")  loadStats();
  if (name === "users")     loadUsers();
  if (name === "logs")      loadLogs();
  if (name === "security")  loadSecurity();
  if (name === "analytics") loadAnalytics();
  if (name === "controls")  loadControls();
}

// ── STATS ──────────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const d = await api("/api/sa/stats");
    Object.entries(d).forEach(([k, v]) => {
      const el = document.getElementById("st-" + k);
      if (el) el.textContent = v;
    });
  } catch(e) { toast(e.message, "error"); }
}

// ── DRILL DOWN from overview cards ────────────────────────────────────────
window.drillDown = async (type) => {
  const modal    = document.getElementById("drill-modal");
  const titleEl  = document.getElementById("modal-title");
  const bodyEl   = document.getElementById("modal-body");
  bodyEl.innerHTML = `<div style="text-align:center;padding:20px"><span class="spin"></span></div>`;
  modal.classList.add("open");

  try {
    if (type === "total_users" || type === "admins" || type === "users") {
      const d = await api("/api/sa/users");
      let list = d.users;
      if (type === "admins")  list = list.filter(u => u.role === "admin");
      if (type === "users")   list = list.filter(u => u.role === "user");
      titleEl.textContent = type === "admins" ? "Admins" : type === "users" ? "Users" : "All Users";
      bodyEl.innerHTML = `<table style="width:100%;border-collapse:collapse">
        <thead><tr><th style="padding:8px;text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase">Email</th>
        <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase">Role</th>
        <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase">Status</th>
        <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase">Created</th></tr></thead>
        <tbody>${list.map(u => `<tr style="border-bottom:1px solid rgba(35,45,69,.5)">
          <td style="padding:8px;font-size:13px;color:var(--dt)">${u.email}</td>
          <td style="padding:8px">${roleBadge(u.role)}</td>
          <td style="padding:8px">${statusBadge(u.status)}</td>
          <td style="padding:8px;font-size:11px;color:var(--mut)">${fmtDate(u.created_at)}</td>
        </tr>`).join("")}</tbody>
      </table>`;
    }
    else if (type === "active_users" || type === "blocked_users") {
      const d = await api("/api/sa/users");
      const st = type === "active_users" ? "active" : "blocked";
      const list = d.users.filter(u => u.status === st);
      titleEl.textContent = type === "active_users" ? "Active Users" : "Blocked Users";
      bodyEl.innerHTML = `<table style="width:100%;border-collapse:collapse">
        <thead><tr>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase">Email</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase">Name</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase">Role</th>
        </tr></thead>
        <tbody>${list.map(u=>`<tr style="border-bottom:1px solid rgba(35,45,69,.5)">
          <td style="padding:8px;font-size:13px;color:var(--dt)">${u.email}</td>
          <td style="padding:8px;font-size:13px;color:var(--mut)">${u.name||"—"}</td>
          <td style="padding:8px">${roleBadge(u.role)}</td>
        </tr>`).join("")}
        ${!list.length?`<tr><td colspan="3" style="padding:16px;text-align:center;color:var(--mut)">None found</td></tr>`:""}
        </tbody></table>`;
    }
    else if (type === "success_logins" || type === "failed_logins") {
      const st = type === "success_logins" ? "success" : "failed";
      const d = await api("/api/sa/logs?limit=200");
      const list = d.logs.filter(l => l.status === st);
      titleEl.textContent = type === "success_logins" ? "Successful Logins" : "Failed Logins";
      bodyEl.innerHTML = `<table style="width:100%;border-collapse:collapse">
        <thead><tr>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Email</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Action</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Risk</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Time</th>
        </tr></thead>
        <tbody>${list.slice(0,50).map(l=>`<tr style="border-bottom:1px solid rgba(35,45,69,.5)">
          <td style="padding:8px;font-size:12px;color:var(--dt)">${l.email||"—"}</td>
          <td style="padding:8px;font-size:12px;color:var(--mut)">${l.action||"—"}</td>
          <td style="padding:8px">${riskBadge(l.risk_label||"low")}</td>
          <td style="padding:8px;font-size:11px;color:var(--mut)">${fmtDate(l.timestamp)}</td>
        </tr>`).join("")}</tbody></table>`;
    }
    else if (type === "high_risk") {
      const d = await api("/api/sa/security");
      titleEl.textContent = "High Risk Events";
      bodyEl.innerHTML = `<table style="width:100%;border-collapse:collapse">
        <thead><tr>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Email</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Action</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Device</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Location</th>
          <th style="padding:8px;text-align:left;color:var(--mut);font-size:11px">Time</th>
        </tr></thead>
        <tbody>${d.alerts.map(l=>`<tr style="border-bottom:1px solid rgba(35,45,69,.5)">
          <td style="padding:8px;font-size:12px;color:var(--dt)">${l.email||"—"}</td>
          <td style="padding:8px;font-size:12px;color:var(--mut)">${l.action||"—"}</td>
          <td style="padding:8px;font-size:12px;color:var(--mut)">${l.device||"—"}</td>
          <td style="padding:8px;font-size:12px;color:var(--mut)">${l.location||"—"}</td>
          <td style="padding:8px;font-size:11px;color:var(--mut)">${fmtDate(l.timestamp)}</td>
        </tr>`).join("")}
        ${!d.alerts.length?`<tr><td colspan="5" style="padding:16px;text-align:center;color:var(--mut)">No high-risk events 🎉</td></tr>`:""}
        </tbody></table>`;
    }
    else if (type === "events") {
      // navigate to logs section
      modal.classList.remove("open");
      document.querySelector('[data-s="logs"]').click();
      return;
    }
  } catch(e) { bodyEl.innerHTML=`<p style="color:var(--danger)">${e.message}</p>`; }
};

// close modal on background click
document.getElementById("drill-modal")?.addEventListener("click", function(e) {
  if (e.target === this) this.classList.remove("open");
});

// ── USERS ──────────────────────────────────────────────────────────────────
let allUsers = [];
async function loadUsers() {
  loadingRow("users-tb", 7);
  try {
    const d = await api("/api/sa/users");
    allUsers = d.users;
    renderUsers(allUsers);
  } catch(e) { toast(e.message, "error"); }
}

function renderUsers(users) {
  const tb = document.getElementById("users-tb");
  const lbl = document.getElementById("user-count-label");
  if (lbl) lbl.textContent = `${users.length} user${users.length!==1?"s":""}`;
  if (!users.length) {
    tb.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:18px;color:var(--mut)">No users found</td></tr>`;
    return;
  }
  tb.innerHTML = users.map(u => `
    <tr>
      <td style="font-size:11px;font-family:var(--mono);color:var(--mut)">#${u.id}</td>
      <td style="font-size:13px">${u.email}</td>
      <td style="font-size:13px;color:var(--mut)">${u.name || "—"}</td>
      <td>${roleBadge(u.role)}</td>
      <td>${statusBadge(u.status)}</td>
      <td style="font-size:11px;color:var(--mut)">${fmtDate(u.created_at)}</td>
      <td style="white-space:nowrap">
        ${u.email !== "sanjay22522g@gmail.com" ? `
          <select class="rsel" data-uid="${u.id}" style="background:var(--card2);border:1px solid var(--bdr);color:var(--dt);border-radius:6px;padding:4px 7px;font-size:11px;margin-right:4px">
            <option value="">Role…</option>
            <option value="super_admin" ${u.role==="super_admin"?"selected":""}>Super Admin</option>
            <option value="admin"       ${u.role==="admin"?"selected":""}>Admin</option>
            <option value="user"        ${u.role==="user"?"selected":""}>User</option>
          </select>
          <button class="btn ${u.status==="active"?"btn-d":"btn-s"}" onclick="window.togSt(${u.id},'${u.status}')" style="margin-right:4px">
            ${u.status==="active"?"Block":"Unblock"}
          </button>
          <button class="btn btn-o" onclick="window.delUsr(${u.id},'${u.email}')">Delete</button>
        ` : `<span style="font-size:12px;color:var(--warn)">🔒 Protected</span>`}
      </td>
    </tr>`).join("");

  document.querySelectorAll(".rsel").forEach(sel => {
    sel.addEventListener("change", async () => {
      if (!sel.value) return;
      try {
        await api(`/api/sa/users/${sel.dataset.uid}/role`, { method:"PUT", body:JSON.stringify({ role:sel.value }) });
        toast("Role updated", "success"); loadUsers();
      } catch(e) { toast(e.message, "error"); sel.value = ""; }
    });
  });
}

window.togSt = async (uid, cur) => {
  const st = cur === "active" ? "blocked" : "active";
  try {
    await api(`/api/sa/users/${uid}/status`, { method:"PUT", body:JSON.stringify({ status:st }) });
    toast(`User ${st}`, "success"); loadUsers();
  } catch(e) { toast(e.message, "error"); }
};
window.delUsr = async (uid, email) => {
  if (!confirm(`Delete ${email}? This cannot be undone.`)) return;
  try {
    await api(`/api/sa/users/${uid}`, { method:"DELETE" });
    toast("User deleted", "success"); loadUsers();
  } catch(e) { toast(e.message, "error"); }
};

document.getElementById("user-search")?.addEventListener("input", filterUsers);
document.getElementById("role-filter")?.addEventListener("change", filterUsers);
document.getElementById("status-filter")?.addEventListener("change", filterUsers);
function filterUsers() {
  const q  = (document.getElementById("user-search")?.value||"").toLowerCase();
  const rf = document.getElementById("role-filter")?.value||"";
  const sf = document.getElementById("status-filter")?.value||"";
  renderUsers(allUsers.filter(u =>
    (!q  || u.email.toLowerCase().includes(q) || (u.name||"").toLowerCase().includes(q)) &&
    (!rf || u.role === rf) &&
    (!sf || u.status === sf)
  ));
}

// ── LOGS ───────────────────────────────────────────────────────────────────
let allLogs = [];
async function loadLogs() {
  loadingRow("logs-tb", 8);
  try {
    const d = await api("/api/sa/logs?limit=200");
    allLogs = d.logs;
    renderLogs(allLogs);
  } catch(e) { toast(e.message, "error"); }
}
function renderLogs(logs) {
  const tb  = document.getElementById("logs-tb");
  const lbl = document.getElementById("log-count-label");
  if (lbl) lbl.textContent = `${logs.length} event${logs.length!==1?"s":""}`;
  if (!logs.length) { tb.innerHTML=`<tr><td colspan="8" style="text-align:center;padding:18px;color:var(--mut)">No logs</td></tr>`; return; }
  tb.innerHTML = logs.map(l => `<tr>
    <td style="font-size:11px;font-family:var(--mono);color:var(--mut)">#${l.user_id||"—"}</td>
    <td style="font-size:12px">${l.email||"—"}</td>
    <td style="font-size:12px;color:var(--mut)">${l.action||"—"}</td>
    <td>${riskBadge(l.risk_label||"low")}</td>
    <td>${statusBadge(l.status||"—")}</td>
    <td style="font-size:11px;color:var(--mut)">${l.device||"—"}</td>
    <td style="font-size:11px;color:var(--mut)">${l.location||"—"}</td>
    <td style="font-size:11px;color:var(--mut)">${fmtDate(l.timestamp)}</td>
  </tr>`).join("");
}
document.getElementById("log-search")?.addEventListener("input", filterLogs);
document.getElementById("log-risk-filter")?.addEventListener("change", filterLogs);
document.getElementById("log-status-filter")?.addEventListener("change", filterLogs);
function filterLogs() {
  const q  = (document.getElementById("log-search")?.value||"").toLowerCase();
  const rf = document.getElementById("log-risk-filter")?.value||"";
  const sf = document.getElementById("log-status-filter")?.value||"";
  renderLogs(allLogs.filter(l =>
    (!q  || (l.email||"").toLowerCase().includes(q) || (l.action||"").includes(q)) &&
    (!rf || (l.risk_label||"low") === rf) &&
    (!sf || l.status === sf)
  ));
}

// ── SECURITY ───────────────────────────────────────────────────────────────
async function loadSecurity() {
  loadingRow("sec-tb", 5);
  try {
    const d = await api("/api/sa/security");
    document.getElementById("alert-count").textContent = d.alerts.length;
    const tb = document.getElementById("sec-tb");
    if (!d.alerts.length) { tb.innerHTML=`<tr><td colspan="5" style="text-align:center;padding:18px;color:var(--mut)">No high-risk events 🎉</td></tr>`; return; }
    tb.innerHTML = d.alerts.map(l => `<tr>
      <td style="font-size:12px">${l.email||"—"}</td>
      <td style="font-size:12px;color:var(--mut)">${l.action||"—"}</td>
      <td style="font-size:12px;color:var(--mut)">${l.device||"—"}</td>
      <td style="font-size:12px;color:var(--mut)">${l.location||"—"}</td>
      <td style="font-size:11px;color:var(--mut)">${fmtDate(l.timestamp)}</td>
    </tr>`).join("");
  } catch(e) { toast(e.message, "error"); }
}

// ── ANALYTICS — full rich charts ───────────────────────────────────────────
let charts = {};
async function loadAnalytics() {
  try {
    const [basic, rich] = await Promise.all([
      api("/api/sa/analytics"),
      api("/api/sa/analytics/rich")
    ]);

    const co = { plugins:{legend:{labels:{color:"#e2e8f0",font:{size:11}}}}, responsive:true, maintainAspectRatio:true };
    const sc = { ticks:{color:"#64748b"}, grid:{color:"#232d45"} };

    // Analytics tabs
    document.querySelectorAll(".atab").forEach(tab => {
      tab.addEventListener("click", () => {
        document.querySelectorAll(".atab").forEach(t=>t.classList.remove("active"));
        document.querySelectorAll(".asec").forEach(s=>s.classList.remove("active"));
        tab.classList.add("active");
        document.getElementById("at-"+tab.dataset.at)?.classList.add("active");
        // lazy render charts for the newly visible tab
        renderTabCharts(tab.dataset.at, basic, rich, co, sc);
      });
    });

    // Render first tab immediately
    renderTabCharts("login", basic, rich, co, sc);

  } catch(e) { toast(e.message, "error"); }
}

function mkChart(id, cfg, chartKey) {
  const ctx = document.getElementById(id)?.getContext("2d");
  if (!ctx) return;
  charts[chartKey]?.destroy();
  charts[chartKey] = new Chart(ctx, cfg);
}

function renderTabCharts(tab, basic, rich, co, sc) {
  if (tab === "login") {
    // 7-day trend
    mkChart("chart-trend7", { type:"line", data:{
      labels: basic.trend.map(t=>t.date.slice(5)),
      datasets:[
        {label:"Success",  data:basic.trend.map(t=>t.success),   borderColor:"#10b981",backgroundColor:"rgba(16,185,129,.1)",tension:.4,fill:true},
        {label:"Failed",   data:basic.trend.map(t=>t.failed),    borderColor:"#f43f5e",backgroundColor:"rgba(244,63,94,.1)",tension:.4,fill:true},
        {label:"High Risk",data:basic.trend.map(t=>t.high_risk), borderColor:"#f59e0b",backgroundColor:"rgba(245,158,11,.1)",tension:.4,fill:true}
      ]}, options:{...co, scales:{x:sc,y:{...sc,beginAtZero:true}}}
    }, "t7");

    // Status breakdown
    const sb = rich.status_breakdown;
    mkChart("chart-status", { type:"pie", data:{
      labels:["Success","Failed","Pending"],
      datasets:[{data:[sb.success||0,sb.failed||0,sb.pending||0],
        backgroundColor:["#10b981","#f43f5e","#f59e0b"],borderColor:"#141926",borderWidth:2}]
    }, options:co }, "ts");

    // 30-day trend
    mkChart("chart-trend30", { type:"bar", data:{
      labels: rich.trend_30days.map(t=>t.date.slice(5)),
      datasets:[{label:"Events",data:rich.trend_30days.map(t=>t.count),backgroundColor:"rgba(79,142,247,.6)",borderRadius:3}]
    }, options:{...co, plugins:{legend:{display:false}}, scales:{x:sc,y:{...sc,beginAtZero:true}}}}, "t30");
  }

  else if (tab === "user") {
    const rd = rich.role_distribution;
    mkChart("chart-roles", { type:"doughnut", data:{
      labels:["Super Admin","Admin","User"],
      datasets:[{data:[rd.super_admin||0,rd.admin||0,rd.user||0],
        backgroundColor:["#f59e0b","#4f8ef7","#10b981"],borderColor:"#141926",borderWidth:2}]
    }, options:co }, "roles");

    // User status from stats
    mkChart("chart-ustatus", { type:"doughnut", data:{
      labels:["Active","Blocked"],
      datasets:[{data:[rich.total_users-(rd.super_admin||0)-(rd.admin||0),rd.super_admin||0],
        backgroundColor:["#10b981","#f43f5e"],borderColor:"#141926",borderWidth:2}]
    }, options:co }, "ustatus");

    // Top locations bar
    const locBars = document.getElementById("loc-bars");
    if (locBars && rich.top_locations?.length) {
      const max = rich.top_locations[0][1];
      locBars.innerHTML = rich.top_locations.map(([loc,count]) => `
        <div class="bar-item">
          <div class="bar-label">${loc}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${(count/max*100).toFixed(0)}%;background:var(--acc)"></div></div>
          <div class="bar-count">${count}</div>
        </div>`).join("");
    }
  }

  else if (tab === "risk") {
    mkChart("chart-risk", { type:"doughnut", data:{
      labels:["Safe","High Risk"],
      datasets:[{data:[basic.risk_distribution.low,basic.risk_distribution.high],
        backgroundColor:["#10b981","#f43f5e"],borderColor:"#141926",borderWidth:2}]
    }, options:co }, "risk");

    const act = rich.action_breakdown;
    mkChart("chart-actions", { type:"bar", data:{
      labels: Object.keys(act),
      datasets:[{label:"Count",data:Object.values(act),backgroundColor:"rgba(124,58,237,.7)",borderRadius:4}]
    }, options:{...co, plugins:{legend:{display:false}}, scales:{x:{...sc,ticks:{...sc.ticks,maxRotation:30}},y:{...sc,beginAtZero:true}}}}, "actions");

    mkChart("chart-highrisk", { type:"line", data:{
      labels: basic.trend.map(t=>t.date.slice(5)),
      datasets:[{label:"High Risk",data:basic.trend.map(t=>t.high_risk),
        borderColor:"#f43f5e",backgroundColor:"rgba(244,63,94,.15)",tension:.4,fill:true}]
    }, options:{...co, plugins:{legend:{display:false}}, scales:{x:sc,y:{...sc,beginAtZero:true}}}}, "highrisk");
  }

  else if (tab === "device") {
    const dev = rich.device_breakdown;
    mkChart("chart-devices", { type:"doughnut", data:{
      labels: Object.keys(dev).length ? Object.keys(dev) : ["No data"],
      datasets:[{data: Object.keys(dev).length ? Object.values(dev) : [1],
        backgroundColor:["#4f8ef7","#f59e0b","#10b981","#f43f5e"],borderColor:"#141926",borderWidth:2}]
    }, options:co }, "dev");

    const locBars2 = document.getElementById("device-loc-bars");
    if (locBars2 && rich.top_locations?.length) {
      const max = rich.top_locations[0][1];
      locBars2.innerHTML = rich.top_locations.map(([loc,count]) => `
        <div class="bar-item">
          <div class="bar-label">${loc}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${(count/max*100).toFixed(0)}%;background:#f59e0b"></div></div>
          <div class="bar-count">${count}</div>
        </div>`).join("");
    } else if (locBars2) {
      locBars2.innerHTML = `<p style="color:var(--mut);padding:12px">No location data yet</p>`;
    }
  }

  else if (tab === "time") {
    const labels = Array.from({length:24},(_,i)=>`${String(i).padStart(2,"0")}:00`);
    mkChart("chart-hourly", { type:"bar", data:{
      labels,
      datasets:[{label:"Logins",data:rich.hourly_activity,
        backgroundColor: rich.hourly_activity.map((_,i) =>
          (i>=6&&i<=9)||i===12||(i>=17&&i<=20) ? "rgba(16,185,129,.7)" : "rgba(79,142,247,.5)"
        ),borderRadius:4}]
    }, options:{...co, plugins:{legend:{display:false}},
      scales:{x:{...sc,ticks:{...sc.ticks,maxRotation:45}},y:{...sc,beginAtZero:true}}}}, "hourly");
  }
}

// ── CONTROLS ───────────────────────────────────────────────────────────────
async function loadControls() {
  try {
    const [stats, rich] = await Promise.all([
      api("/api/sa/stats"),
      api("/api/sa/analytics/rich")
    ]);

    // DB stats
    const dbEl = document.getElementById("ctrl-db-stats");
    if (dbEl) dbEl.textContent = `${rich.total_users} users · ${rich.total_logs} events`;

    // SA email
    const saEl = document.getElementById("ctrl-sa-email");
    if (saEl) {
      // fetch super admin from users list
      const d = await api("/api/sa/users");
      const sa = d.users.find(u => u.role === "super_admin");
      if (sa) saEl.textContent = sa.email;
    }

    // Model status — check if predictions are working
    const msEl = document.getElementById("model-status");
    if (msEl) {
      try {
        await api("/api/sa/analytics"); // if this works, backend is good
        msEl.innerHTML = `<span class="ctrl-badge cb-ok">Active ✓</span>`;
      } catch {
        msEl.innerHTML = `<span class="ctrl-badge cb-warn">Check logs</span>`;
      }
    }
  } catch(e) { console.warn("Controls load error:", e.message); }
}

// ── LOGOUT ─────────────────────────────────────────────────────────────────
document.getElementById("logout-btn").addEventListener("click", async () => {
  try { await api("/api/logout", {method:"POST"}); } catch {}
  clrAuth(); window.location.href="/";
});

load("overview");
