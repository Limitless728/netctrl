/**
 * NetCtrl Pro – Web Dashboard Application Logic
 * Communicates directly with the Rust engine HTTP API (127.0.0.1:8765)
 */

const API_BASE = "http://127.0.0.1:8765";

// Traffic history for sparkline canvas graphs (mac -> array of speeds)
const trafficHistory = new Map();
const MAX_HISTORY_SAMPLES = 25;

// Current state
let devicesList = [];
let filteredSearch = "";
let currentSelectedMacForSpeed = null;
let currentSelectedMacForSites = null;
let currentSitesList = [];
let isScanning = false;
let editingMac = null;

// MAC OUI Vendor Prefix Lookup Table
const VENDOR_PREFIXES = {
  // Apple
  "00:17:f2": { name: "Apple", icon: "🍎" },
  "ac:de:48": { name: "Apple", icon: "🍎" },
  "dc:fb:48": { name: "Intel / PC", icon: "💻" },
  "00:1c:b3": { name: "Apple", icon: "🍎" },
  "bc:d0:74": { name: "Apple", icon: "🍎" },
  "f4:5c:89": { name: "Apple", icon: "🍎" },
  "34:08:bc": { name: "Apple", icon: "🍎" },
  "b8:78:2e": { name: "Apple", icon: "🍎" },
  // Samsung
  "00:12:fb": { name: "Samsung", icon: "📱" },
  "2c:0e:3d": { name: "Samsung", icon: "📱" },
  "54:bf:64": { name: "Samsung", icon: "📱" },
  "80:20:fd": { name: "Samsung", icon: "📱" },
  "94:f6:f2": { name: "Samsung", icon: "📱" },
  "e4:7c:f9": { name: "Samsung", icon: "📱" },
  // Xiaomi
  "28:6c:07": { name: "Xiaomi", icon: "📱" },
  "34:80:0d": { name: "Xiaomi", icon: "📱" },
  "64:cc:2e": { name: "Xiaomi", icon: "📱" },
  "74:23:44": { name: "Xiaomi", icon: "📱" },
  // Huawei / Honor
  "00:e0:fc": { name: "Huawei", icon: "📱" },
  "48:d8:39": { name: "Huawei", icon: "📱" },
  // Intel
  "00:1b:21": { name: "Intel", icon: "💻" },
  "08:84:fb": { name: "Intel", icon: "💻" },
  "24:77:03": { name: "Intel", icon: "💻" },
  // Realtek
  "00:e0:4c": { name: "Realtek", icon: "💻" },
  "52:54:00": { name: "QEMU / VM", icon: "🖥️" },
  // TP-Link
  "14:cc:20": { name: "TP-Link", icon: "📶" },
  "50:c7:bf": { name: "TP-Link", icon: "📶" },
  "b4:b0:24": { name: "Router", icon: "🌐" },
  "c0:06:c3": { name: "TP-Link", icon: "📶" },
  // Espressif / IoT
  "18:fe:34": { name: "Espressif IoT", icon: "💡" },
  "24:6f:28": { name: "Espressif IoT", icon: "💡" },
  "30:ae:a4": { name: "Smart Device", icon: "💡" },
  // Google
  "d8:6c:63": { name: "Google", icon: "📱" },
  "70:3a:cb": { name: "Google Nest", icon: "🔊" },
  // Sony
  "00:13:15": { name: "Sony / PlayStation", icon: "🎮" },
  "f8:46:1c": { name: "PlayStation", icon: "🎮" },
};

function getVendorInfo(mac) {
  if (!mac) return { name: "Device", icon: "💻" };
  const prefix = mac.toLowerCase().substring(0, 8);
  if (VENDOR_PREFIXES[prefix]) {
    return VENDOR_PREFIXES[prefix];
  }
  return { name: "LAN Device", icon: "💻" };
}

// -----------------------------------------------------------------------------
// Formatters
// -----------------------------------------------------------------------------
function formatSpeed(kbps) {
  if (!kbps || kbps <= 0.05) return "0.0 KB/s";
  if (kbps < 1000) return `${kbps.toFixed(1)} KB/s`;
  return `${(kbps / 1024).toFixed(2)} MB/s`;
}

function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatTimestamp(ts) {
  if (!ts) return "";
  if (typeof ts === "number") {
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }
  return String(ts);
}

// -----------------------------------------------------------------------------
// Toast Notifications
// -----------------------------------------------------------------------------
function showToast(message, type = "info") {
  const container = document.getElementById("toastContainer");
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;

  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add("toast-out");
    setTimeout(() => toast.remove(), 250);
  }, 3000);
}

// -----------------------------------------------------------------------------
// API Client
// -----------------------------------------------------------------------------
async function apiGet(endpoint) {
  const res = await fetch(`${API_BASE}${endpoint}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

async function apiPost(endpoint, data = {}) {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

// -----------------------------------------------------------------------------
// Sparkline Mini Traffic Chart
// -----------------------------------------------------------------------------
function updateSparkline(canvas, speed) {
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const mac = canvas.dataset.mac;
  if (!mac) return;

  let history = trafficHistory.get(mac);
  if (!history) {
    history = new Array(MAX_HISTORY_SAMPLES).fill(0);
    trafficHistory.set(mac, history);
  }

  history.push(speed || 0);
  if (history.length > MAX_HISTORY_SAMPLES) {
    history.shift();
  }

  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const maxVal = Math.max(...history, 5); // baseline minimum
  const step = w / (MAX_HISTORY_SAMPLES - 1);

  ctx.beginPath();
  ctx.strokeStyle = speed > 50 ? "#3fb950" : "#58a6ff";
  ctx.lineWidth = 1.8;
  ctx.lineJoin = "round";

  history.forEach((val, idx) => {
    const x = idx * step;
    const y = h - (val / maxVal) * (h - 4) - 2;
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Subtle gradient fill under the line
  ctx.lineTo(w, h);
  ctx.lineTo(0, h);
  ctx.closePath();
  ctx.fillStyle = speed > 50 ? "rgba(63, 185, 80, 0.15)" : "rgba(88, 166, 255, 0.1)";
  ctx.fill();
}

// -----------------------------------------------------------------------------
// Device Table Rendering
// -----------------------------------------------------------------------------
function renderDevicesTable() {
  const tbody = document.getElementById("deviceTableBody");
  const q = filteredSearch.toLowerCase().trim();

  const filtered = devicesList.filter((d) => {
    if (!q) return true;
    const name = (d.display_name || d.name || "").toLowerCase();
    const ip = (d.ip || "").toLowerCase();
    const mac = (d.mac || "").toLowerCase();
    return name.includes(q) || ip.includes(q) || mac.includes(q);
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr class="empty-placeholder">
        <td colspan="10">
          <div class="empty-state">
            <p>No matching devices found.</p>
          </div>
        </td>
      </tr>
    `;
    return;
  }

  // Calculate totals
  let totalDl = 0;
  let totalUl = 0;
  let countMonitored = 0;
  let countBlocked = 0;

  devicesList.forEach((d) => {
    totalDl += d.dl_speed || 0;
    totalUl += d.ul_speed || 0;
    if (d.is_monitored) countMonitored++;
    if (d.is_blocked) countBlocked++;
  });

  const totalDlEl = document.getElementById("totalDlSpeed");
  const totalUlEl = document.getElementById("totalUlSpeed");
  const countTotalEl = document.getElementById("countTotal");
  const countMonitoredEl = document.getElementById("countMonitored");
  const countBlockedEl = document.getElementById("countBlocked");

  if (totalDlEl) totalDlEl.textContent = formatSpeed(totalDl);
  if (totalUlEl) totalUlEl.textContent = formatSpeed(totalUl);
  if (countTotalEl) countTotalEl.textContent = devicesList.length;
  if (countMonitoredEl) countMonitoredEl.textContent = countMonitored;
  if (countBlockedEl) countBlockedEl.textContent = countBlocked;

  // If a device name is currently being edited, do NOT touch table DOM to prevent interruption
  if (editingMac !== null) {
    return;
  }

  // Smooth in-place update if existing rows already match filtered list
  const existingRows = Array.from(tbody.querySelectorAll("tr.device-row"));
  const canUpdateInPlace =
    existingRows.length === filtered.length &&
    filtered.every((d, idx) => existingRows[idx] && existingRows[idx].dataset.mac === d.mac);

  if (canUpdateInPlace) {
    filtered.forEach((d, idx) => {
      const row = existingRows[idx];
      const totalBytes = (d.total_dl_bytes || 0) + (d.total_ul_bytes || 0);

      row.classList.toggle("is-blocked", !!d.is_blocked);

      const nameTextEl = row.querySelector(".device-name-text");
      const vendor = getVendorInfo(d.mac);
      const displayName = d.display_name || d.name || vendor.name;
      if (nameTextEl && nameTextEl.textContent !== displayName) {
        nameTextEl.textContent = displayName;
      }

      const dlSpan = row.querySelector(".speed-row.dl span");
      if (dlSpan) dlSpan.textContent = formatSpeed(d.dl_speed);
      const ulSpan = row.querySelector(".speed-row.ul span");
      if (ulSpan) ulSpan.textContent = formatSpeed(d.ul_speed);

      const canvas = row.querySelector(".sparkline-canvas");
      if (canvas) {
        updateSparkline(canvas, (d.dl_speed || 0) + (d.ul_speed || 0));
      }

      const totalSpan = row.querySelector(".total-usage-text");
      if (totalSpan) totalSpan.textContent = formatBytes(totalBytes);

      const monInput = row.querySelector(".toggle-switch.monitor input");
      if (monInput && monInput.checked !== !!d.is_monitored) {
        monInput.checked = !!d.is_monitored;
      }

      const blkInput = row.querySelector(".toggle-switch.block input");
      if (blkInput && blkInput.checked !== !!d.is_blocked) {
        blkInput.checked = !!d.is_blocked;
      }

      const limitBtn = row.querySelector(".speed-limit-badge");
      if (limitBtn) {
        const isLimited = d.speed_limit_kbps && d.speed_limit_kbps > 0;
        const limitText = isLimited ? `${d.speed_limit_kbps} KB/s` : "Unlimited";
        limitBtn.classList.toggle("limited", isLimited);
        const span = limitBtn.querySelector("span");
        if (span && span.textContent !== limitText) {
          span.textContent = limitText;
        }
      }
    });
    return;
  }

  tbody.innerHTML = "";

  filtered.forEach((d) => {
    const isLocal = d.is_local;
    const vendor = getVendorInfo(d.mac);
    const displayName = d.display_name || d.name || vendor.name;
    const totalBytes = (d.total_dl_bytes || 0) + (d.total_ul_bytes || 0);

    const row = document.createElement("tr");
    row.className = `device-row ${isLocal ? "is-local" : ""} ${d.is_blocked ? "is-blocked" : ""}`;
    row.dataset.mac = d.mac;

    // 1. Device Name & Vendor Cell
    const tdDevice = document.createElement("td");
    tdDevice.innerHTML = `
      <div class="device-cell">
        <div class="vendor-icon-badge" title="${vendor.name}">${vendor.icon}</div>
        <div class="device-title-wrap">
          <div class="device-name-container">
            <span class="device-name-text" data-mac="${d.mac}">${displayName}</span>
            ${!isLocal ? `<button class="btn-rename" data-mac="${d.mac}" title="Rename Device">✏️</button>` : `<span class="badge-tag badge-local">This PC</span>`}
          </div>
          <span class="device-vendor-label">${vendor.name}</span>
        </div>
      </div>
    `;

    // 2. IP Address
    const tdIp = document.createElement("td");
    tdIp.innerHTML = `<span class="copyable-badge monospace" title="Click to copy IP">${d.ip}</span>`;
    tdIp.querySelector(".copyable-badge").addEventListener("click", () => copyToClipboard(d.ip, "IP Address copied"));

    // 3. MAC Address
    const tdMac = document.createElement("td");
    tdMac.innerHTML = `<span class="copyable-badge monospace" title="Click to copy MAC">${d.mac}</span>`;
    tdMac.querySelector(".copyable-badge").addEventListener("click", () => copyToClipboard(d.mac, "MAC copied"));

    // 4. Live Speed Gauge
    const tdSpeed = document.createElement("td");
    tdSpeed.innerHTML = `
      <div class="speed-gauge-wrap">
        <div class="speed-row dl" title="Download Speed">
          <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 5v14M19 12l-7 7-7-7"/></svg>
          <span>${formatSpeed(d.dl_speed)}</span>
        </div>
        <div class="speed-row ul" title="Upload Speed">
          <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 19V5M5 12l7-7 7 7"/></svg>
          <span>${formatSpeed(d.ul_speed)}</span>
        </div>
      </div>
    `;

    // 5. Activity Sparkline Canvas
    const tdGraph = document.createElement("td");
    const canvas = document.createElement("canvas");
    canvas.className = "sparkline-canvas";
    canvas.width = 80;
    canvas.height = 24;
    canvas.dataset.mac = d.mac;
    tdGraph.appendChild(canvas);
    updateSparkline(canvas, (d.dl_speed || 0) + (d.ul_speed || 0));

    // 6. Total Usage
    const tdTotal = document.createElement("td");
    tdTotal.innerHTML = `<span class="total-usage-text">${formatBytes(totalBytes)}</span>`;

    // 7. Monitor Toggle
    const tdMonitor = document.createElement("td");
    tdMonitor.className = "text-center";
    if (isLocal) {
      tdMonitor.innerHTML = `<span style="color:var(--text-muted)">—</span>`;
    } else {
      tdMonitor.innerHTML = `
        <label class="toggle-switch monitor" title="Toggle ARP Spoofing Monitor">
          <input type="checkbox" ${d.is_monitored ? "checked" : ""}>
          <span class="toggle-slider"></span>
        </label>
      `;
      tdMonitor.querySelector("input").addEventListener("change", (e) => {
        handleToggleMonitor(d.mac, e.target.checked);
      });
    }

    // 8. Block Toggle
    const tdBlock = document.createElement("td");
    tdBlock.className = "text-center";
    if (isLocal) {
      tdBlock.innerHTML = `<span style="color:var(--text-muted)">—</span>`;
    } else {
      tdBlock.innerHTML = `
        <label class="toggle-switch block" title="Block Internet Access">
          <input type="checkbox" ${d.is_blocked ? "checked" : ""}>
          <span class="toggle-slider"></span>
        </label>
      `;
      tdBlock.querySelector("input").addEventListener("change", (e) => {
        handleToggleBlock(d.mac, e.target.checked);
      });
    }

    // 9. Speed Limit Badge/Button
    const tdLimit = document.createElement("td");
    if (isLocal) {
      tdLimit.innerHTML = `<span style="color:var(--text-muted)">—</span>`;
    } else {
      const isLimited = d.speed_limit_kbps && d.speed_limit_kbps > 0;
      const limitText = isLimited ? `${d.speed_limit_kbps} KB/s` : "Unlimited";
      tdLimit.innerHTML = `
        <button class="speed-limit-badge ${isLimited ? "limited" : ""}" title="Set Speed Limit">
          <span>${limitText}</span>
        </button>
      `;
      tdLimit.querySelector("button").addEventListener("click", () => {
        openSpeedLimitModal(d);
      });
    }

    // 10. Sites Visited Button
    const tdSites = document.createElement("td");
    tdSites.className = "text-center";
    if (isLocal) {
      tdSites.innerHTML = `<span style="color:var(--text-muted)">—</span>`;
    } else {
      tdSites.innerHTML = `<button class="btn-sites" title="View Visited Sites">Sites</button>`;
      tdSites.querySelector("button").addEventListener("click", () => {
        openSitesDrawer(d);
      });
    }

    // Append cells
    row.appendChild(tdDevice);
    row.appendChild(tdIp);
    row.appendChild(tdMac);
    row.appendChild(tdSpeed);
    row.appendChild(tdGraph);
    row.appendChild(tdTotal);
    row.appendChild(tdMonitor);
    row.appendChild(tdBlock);
    row.appendChild(tdLimit);
    row.appendChild(tdSites);

    // Setup Inline Rename listeners
    const nameEl = row.querySelector(".device-name-text");
    const renameBtn = row.querySelector(".btn-rename");
    if (nameEl && !isLocal) {
      nameEl.addEventListener("dblclick", () => startInlineRename(nameEl, d.mac));
    }
    if (renameBtn) {
      renameBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        startInlineRename(nameEl, d.mac);
      });
    }

    tbody.appendChild(row);
  });
}

// -----------------------------------------------------------------------------
// Inline Rename
// -----------------------------------------------------------------------------
function startInlineRename(nameEl, mac) {
  if (!nameEl) return;
  editingMac = mac;
  const currentText = nameEl.textContent;
  const input = document.createElement("input");
  input.type = "text";
  input.value = currentText;
  input.className = "inline-rename-input";
  input.style.cssText = "background:var(--bg-primary);border:1px solid var(--border-focus);color:#fff;padding:2px 6px;border-radius:4px;font-size:12px;outline:none;width:140px;";

  nameEl.replaceWith(input);
  input.focus();
  input.select();

  let finished = false;
  const finish = async (save) => {
    if (finished) return;
    finished = true;
    editingMac = null;

    if (save) {
      const val = input.value.trim();
      if (val && val !== currentText) {
        try {
          await apiPost("/api/set-name", { mac: mac, display_name: val });
          showToast(`Renamed to "${val}"`, "success");
          // Update local object and bridge
          const dev = devicesList.find((x) => x.mac === mac);
          if (dev) {
            dev.display_name = val;
            if (window.pywebview && window.pywebview.api) {
              window.pywebview.api.save_device_name(dev.ip, val).catch(() => {});
            }
          }
        } catch (err) {
          showToast(`Rename failed: ${err.message}`, "error");
        }
      }
    }
    renderDevicesTable();
  };

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      finish(true);
    } else if (e.key === "Escape") {
      e.preventDefault();
      finish(false);
    }
  });
  input.addEventListener("blur", () => {
    finish(true);
  });
}

// -----------------------------------------------------------------------------
// User Control Handlers
// -----------------------------------------------------------------------------
async function handleToggleMonitor(mac, state) {
  try {
    await apiPost("/api/monitor", { mac, monitored: state });
    showToast(state ? "Monitoring enabled" : "Monitoring disabled", "info");
    const dev = devicesList.find((x) => x.mac === mac);
    if (dev) dev.is_monitored = state;
  } catch (err) {
    showToast(`Error toggling monitor: ${err.message}`, "error");
    renderDevicesTable();
  }
}

async function handleToggleBlock(mac, state) {
  try {
    await apiPost("/api/block", { mac, blocked: state });
    showToast(state ? "🚫 Device blocked from internet" : "✓ Device unblocked", state ? "warning" : "success");
    const dev = devicesList.find((x) => x.mac === mac);
    if (dev) dev.is_blocked = state;
  } catch (err) {
    showToast(`Error blocking device: ${err.message}`, "error");
    renderDevicesTable();
  }
}

// -----------------------------------------------------------------------------
// Speed Limit Modal
// -----------------------------------------------------------------------------
function openSpeedLimitModal(device) {
  currentSelectedMacForSpeed = device.mac;
  document.getElementById("speedModalDeviceName").textContent = device.display_name || device.name || "Device";
  document.getElementById("speedModalDeviceIp").textContent = `${device.ip} (${device.mac})`;

  const modal = document.getElementById("speedModal");
  const customInput = document.getElementById("customSpeedInput");
  customInput.value = device.speed_limit_kbps || "";

  // Highlight active preset
  document.querySelectorAll(".btn-preset").forEach((b) => {
    const sp = parseInt(b.dataset.speed, 10);
    b.classList.toggle("active", sp === (device.speed_limit_kbps || 0));
  });

  modal.classList.remove("hidden");
}

function closeSpeedLimitModal() {
  document.getElementById("speedModal").classList.add("hidden");
  currentSelectedMacForSpeed = null;
}

async function applySpeedLimit(kbps) {
  if (!currentSelectedMacForSpeed) return;
  try {
    await apiPost("/api/speed", {
      mac: currentSelectedMacForSpeed,
      speed_limit_kbps: kbps,
    });
    showToast(kbps > 0 ? `Speed limit set to ${kbps} KB/s` : "Speed limit removed (Unlimited)", "success");
    const dev = devicesList.find((x) => x.mac === currentSelectedMacForSpeed);
    if (dev) dev.speed_limit_kbps = kbps;
    closeSpeedLimitModal();
    renderDevicesTable();
  } catch (err) {
    showToast(`Error applying speed: ${err.message}`, "error");
  }
}

// -----------------------------------------------------------------------------
// Sites Visited Drawer
// -----------------------------------------------------------------------------
async function openSitesDrawer(device) {
  currentSelectedMacForSites = device.mac;
  const drawer = document.getElementById("sitesDrawer");
  document.getElementById("sitesDrawerSubtitle").textContent = `${device.display_name || device.name} • ${device.ip}`;
  drawer.classList.remove("hidden");

  await loadSitesForDevice(device.mac);
}

function closeSitesDrawer() {
  document.getElementById("sitesDrawer").classList.add("hidden");
  currentSelectedMacForSites = null;
  currentSitesList = [];
}

async function loadSitesForDevice(mac) {
  const listEl = document.getElementById("sitesList");
  listEl.innerHTML = `<li class="empty-sites"><div class="spinner"></div></li>`;

  try {
    const res = await apiGet(`/api/sites/${mac}`);
    currentSitesList = res.visits || [];
    renderSitesList();
  } catch (err) {
    listEl.innerHTML = `<li class="empty-sites" style="color:var(--accent-red)">Failed to load sites: ${err.message}</li>`;
  }
}

function renderSitesList() {
  const listEl = document.getElementById("sitesList");
  const filter = (document.getElementById("sitesSearchInput").value || "").toLowerCase().trim();

  const filtered = currentSitesList.filter((s) => !filter || s.domain.toLowerCase().includes(filter));

  if (filtered.length === 0) {
    listEl.innerHTML = `<li class="empty-sites">No visited sites matching filter.</li>`;
    return;
  }

  listEl.innerHTML = "";
  filtered.forEach((site) => {
    const li = document.createElement("li");
    li.className = "site-item";
    li.innerHTML = `
      <span class="site-domain" title="Click to copy">${escapeHtml(site.domain)}</span>
      <span class="site-time">${escapeHtml(formatTimestamp(site.timestamp))}</span>
    `;
    li.querySelector(".site-domain").addEventListener("click", () => {
      copyToClipboard(site.domain, "Domain copied");
    });
    listEl.appendChild(li);
  });
}

// -----------------------------------------------------------------------------
// Helpers & Actions
// -----------------------------------------------------------------------------
function copyToClipboard(text, message = "Copied to clipboard") {
  navigator.clipboard.writeText(text).then(() => {
    showToast(message, "info");
  }).catch(() => {
    showToast("Failed to copy", "error");
  });
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  const s = String(str);
  return s.replace(/[&<>"']/g, function (m) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m];
  });
}

// Rescan LAN Sweep
async function triggerRescan() {
  if (isScanning) return;
  isScanning = true;
  const btn = document.getElementById("btnRescan");
  const icon = btn.querySelector(".spin-icon");
  icon.classList.add("spinning");
  btn.disabled = true;

  try {
    showToast("Starting ARP broadcast scan on /24 subnet...", "info");
    const res = await apiPost("/api/scan");
    showToast(`Scan complete: Discovered ${res.new_devices || 0} device(s)`, "success");
    await fetchDevices();
  } catch (err) {
    showToast(`Scan error: ${err.message}`, "error");
  } finally {
    isScanning = false;
    icon.classList.remove("spinning");
    btn.disabled = false;
  }
}

// Emergency Restore All
async function triggerRestoreAll() {
  if (!confirm("Are you sure you want to un-monitor and unblock all devices on your LAN?")) {
    return;
  }
  try {
    const res = await apiPost("/api/restore-all");
    showToast(`LAN restored! ${res.count || 0} device(s) un-monitored.`, "success");
    await fetchDevices();
  } catch (err) {
    showToast(`Restore error: ${err.message}`, "error");
  }
}

// -----------------------------------------------------------------------------
// Data Sync Loop
// -----------------------------------------------------------------------------
async function fetchStatus() {
  try {
    const st = await apiGet("/api/status");
    if (st && st.ok) {
      if (st.interface) document.getElementById("ifaceLabel").textContent = `Gateway (${st.interface})`;
      if (st.gateway_ip) document.getElementById("gatewayIpText").textContent = st.gateway_ip;
      if (st.gateway_mac) document.getElementById("gatewayMacText").textContent = st.gateway_mac;
      if (st.local_ip) document.getElementById("localIpText").textContent = st.local_ip;
      if (st.local_mac) document.getElementById("localMacText").textContent = st.local_mac;
    }
  } catch (e) {
    // Non-fatal, status will retry
  }
}

async function fetchDevices() {
  try {
    const payload = await apiGet("/api/devices");
    devicesList = payload.devices || [];

    document.getElementById("engineStatusText").textContent = "Rust Engine Active";
    document.getElementById("engineBadge").querySelector(".status-dot").className = "status-dot pulsing";
    document.getElementById("lastUpdatedText").textContent = `Updated: ${new Date().toLocaleTimeString()}`;

    renderDevicesTable();
  } catch (err) {
    document.getElementById("engineStatusText").textContent = "Engine Reconnecting...";
    document.getElementById("engineBadge").querySelector(".status-dot").className = "status-dot";
  }
}

// -----------------------------------------------------------------------------
// Event Listeners
// -----------------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  // Rescan & Restore
  document.getElementById("btnRescan").addEventListener("click", triggerRescan);
  document.getElementById("btnRestoreAll").addEventListener("click", triggerRestoreAll);

  // Search
  const searchInput = document.getElementById("searchInput");
  const searchClear = document.getElementById("searchClear");

  searchInput.addEventListener("input", (e) => {
    filteredSearch = e.target.value;
    searchClear.classList.toggle("hidden", !filteredSearch);
    renderDevicesTable();
  });

  searchClear.addEventListener("click", () => {
    searchInput.value = "";
    filteredSearch = "";
    searchClear.classList.add("hidden");
    renderDevicesTable();
  });

  // Speed Modal Listeners
  const speedModal = document.getElementById("speedModal");
  document.getElementById("btnSpeedModalClose").addEventListener("click", closeSpeedLimitModal);
  document.getElementById("btnSpeedCancel").addEventListener("click", closeSpeedLimitModal);

  // Close speed modal when clicking on the blurred backdrop
  speedModal.addEventListener("click", (e) => {
    if (e.target === speedModal) {
      closeSpeedLimitModal();
    }
  });

  document.querySelectorAll(".btn-preset").forEach((btn) => {
    btn.addEventListener("click", () => {
      const speed = parseInt(btn.dataset.speed, 10);
      applySpeedLimit(speed);
    });
  });

  document.getElementById("btnSpeedApply").addEventListener("click", () => {
    const custom = parseInt(document.getElementById("customSpeedInput").value, 10);
    if (!isNaN(custom) && custom > 0) {
      applySpeedLimit(custom);
    } else {
      applySpeedLimit(0); // Unlimited
    }
  });

  // Sites Drawer Listeners
  const sitesDrawer = document.getElementById("sitesDrawer");
  document.getElementById("btnSitesDrawerClose").addEventListener("click", closeSitesDrawer);
  document.getElementById("sitesSearchInput").addEventListener("input", renderSitesList);

  // Close sites drawer when clicking on the blurred backdrop
  sitesDrawer.addEventListener("click", (e) => {
    if (e.target === sitesDrawer) {
      closeSitesDrawer();
    }
  });

  // Global Escape key listener to dismiss open modal/drawer
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (!speedModal.classList.contains("hidden")) {
        closeSpeedLimitModal();
      }
      if (!sitesDrawer.classList.contains("hidden")) {
        closeSitesDrawer();
      }
    }
  });

  document.getElementById("btnCopyAllDomains").addEventListener("click", () => {
    if (!currentSitesList || currentSitesList.length === 0) return;
    const text = currentSitesList.map((x) => x.domain).join("\n");
    copyToClipboard(text, "All domains copied");
  });

  document.getElementById("btnClearDomainHistory").addEventListener("click", async () => {
    if (!currentSelectedMacForSites) return;
    try {
      await apiPost(`/api/sites/${currentSelectedMacForSites}/clear`);
      currentSitesList = [];
      renderSitesList();
      showToast("Visit history cleared", "info");
    } catch (e) {
      showToast(`Failed to clear: ${e.message}`, "error");
    }
  });

  // Initial load
  fetchStatus();
  fetchDevices();

  // Polling intervals
  setInterval(fetchDevices, 1000);
  setInterval(fetchStatus, 15000);
});

// PyWebView native bridge integration
window.addEventListener("pywebviewready", async () => {
  if (window.pywebview && window.pywebview.api) {
    try {
      const ctx = await window.pywebview.api.get_context();
      if (ctx) {
        if (ctx.local_ip) document.getElementById("localIpText").textContent = ctx.local_ip;
        if (ctx.local_mac) document.getElementById("localMacText").textContent = ctx.local_mac;
        if (ctx.gateway_ip) document.getElementById("gatewayIpText").textContent = ctx.gateway_ip;
        if (ctx.gateway_mac) document.getElementById("gatewayMacText").textContent = ctx.gateway_mac;
        if (ctx.backend_label) {
          document.querySelector(".brand-text h1 span").textContent = ctx.backend_label.replace(/[()]/g, "");
        }
      }
    } catch (e) {
      console.warn("pywebview bridge context error:", e);
    }
  }
});
