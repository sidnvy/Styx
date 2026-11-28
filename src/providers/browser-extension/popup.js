function render(status) {
  const hostEl = document.getElementById("host-status");
  const countEl = document.getElementById("attached-count");
  const styxTabsEl = document.getElementById("styx-tabs-count");
  const closeStyxBtn = document.getElementById("close-styx-btn");
  const errEl = document.getElementById("error-box");
  const idEl = document.getElementById("ext-id");

  if (!status) {
    hostEl.textContent = "Unavailable";
    hostEl.className = "badge err";
    return;
  }

  if (status.hostConnected) {
    hostEl.textContent = "Connected";
    hostEl.className = "badge ok";
  } else if (status.nativeConnected) {
    hostEl.textContent = "Waiting for Styx Host";
    hostEl.className = "badge warn";
  } else {
    hostEl.textContent = "Native bridge disconnected";
    hostEl.className = "badge err";
  }

  const styxTabCount = Number(status.isolatedTabCount ?? 0);
  countEl.textContent = String(status.attachedTabCount ?? 0);
  styxTabsEl.textContent = String(styxTabCount);
  closeStyxBtn.textContent =
    styxTabCount > 0 ? `Close Styx tabs (${styxTabCount})` : "Close Styx tabs";
  closeStyxBtn.disabled = styxTabCount === 0;
  idEl.textContent = status.extensionId || chrome.runtime.id || "";
  errEl.textContent = status.lastError ? `Last error: ${status.lastError}` : "";
}

function refresh() {
  chrome.runtime.sendMessage({ type: "styx.popup.getStatus" }, render);
}

document.getElementById("reconnect-btn").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "styx.popup.reconnect" }, () => {
    setTimeout(refresh, 250);
  });
});

document.getElementById("detach-btn").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "styx.popup.detachAll" }, render);
});

document.getElementById("close-styx-btn").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "styx.popup.closeStyxTabs" }, render);
});

refresh();
