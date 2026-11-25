const NATIVE_HOST_NAME = "com.styx.browser_bridge";
const KEEPALIVE_ALARM = "styx-bridge-keepalive";

function isAttachableUrl(rawUrl) {
  if (typeof rawUrl !== "string" || rawUrl.length === 0) {
    return false;
  }
  const lower = rawUrl.toLowerCase();
  if (
    lower.startsWith("chrome://") ||
    lower.startsWith("chrome-extension://") ||
    lower.startsWith("devtools://") ||
    lower.startsWith("edge://") ||
    lower.startsWith("chrome-search://") ||
    lower.startsWith("view-source:") ||
    lower.startsWith("about:srcdoc")
  ) {
    return false;
  }
  return (
    lower.startsWith("http://") ||
    lower.startsWith("https://") ||
    lower.startsWith("file://") ||
    lower === "about:blank"
  );
}

function parseBrowserVersion(userAgent) {
  if (typeof userAgent !== "string" || userAgent.length === 0) {
    return "Chrome/Extension-Bridge";
  }
  const edgeMatch = userAgent.match(/Edg\/([\d.]+)/);
  if (edgeMatch) {
    return `Edge/${edgeMatch[1]}`;
  }
  const chromeMatch = userAgent.match(/Chrome\/([\d.]+)/);
  if (chromeMatch) {
    return `Chrome/${chromeMatch[1]}`;
  }
  return "Chrome/Extension-Bridge";
}

function normalizeTab(tab) {
  return {
    id: tab.id,
    url: tab.url || tab.pendingUrl || "about:blank",
    title: tab.title || "",
    active: Boolean(tab.active),
    windowId: tab.windowId,
  };
}

function createExtensionController(chromeApi, env = {}) {
  const userAgent =
    typeof env.userAgent === "string"
      ? env.userAgent
      : typeof navigator !== "undefined" && navigator.userAgent
        ? navigator.userAgent
        : "Mozilla/5.0 Chrome/130.0.0.0";
  const setTimeoutFn = env.setTimeout || setTimeout;
  const clearTimeoutFn = env.clearTimeout || clearTimeout;

  let port = null;
  let hostConnected = false;
  let lastError = null;
  let reconnectTimer = null;
  let reconnectAttempt = 0;
  const attachedTabs = new Set();

  function postToBridge(message) {
    if (!port) {
      return false;
    }
    try {
      port.postMessage(message);
      return true;
    } catch (err) {
      lastError = err?.message || String(err);
      port = null;
      hostConnected = false;
      scheduleReconnect();
      return false;
    }
  }

  function emitEvent(event, params) {
    if (!hostConnected || !port) {
      return;
    }
    postToBridge({ event, params });
  }

  async function listAttachableTabs() {
    const tabs = await chromeApi.tabs.query({});
    return tabs
      .filter((tab) => typeof tab.id === "number" && isAttachableUrl(tab.url || tab.pendingUrl))
      .map(normalizeTab);
  }

  async function sendHello() {
    if (!port || !hostConnected) {
      return;
    }
    const tabs = await listAttachableTabs().catch(() => []);
    postToBridge({
      event: "extension.hello",
      params: {
        extensionId: chromeApi.runtime.id || "",
        userAgent,
        browser: parseBrowserVersion(userAgent),
        tabs,
      },
    });
  }

  async function detachTabSafe(tabId) {
    attachedTabs.delete(tabId);
    try {
      await chromeApi.debugger.detach({ tabId });
    } catch (err) {
      const msg = String(err?.message || err || "");
      if (!msg.toLowerCase().includes("not attached")) {
        throw err;
      }
    }
  }

  async function detachAllTabs() {
    const tabIds = Array.from(attachedTabs);
    attachedTabs.clear();
    let detached = 0;
    for (const tabId of tabIds) {
      try {
        await chromeApi.debugger.detach({ tabId });
        detached += 1;
      } catch {
        // Tab may already be closed or manually detached.
      }
    }
    return { detached };
  }

  async function handleRpc(id, method, params = {}) {
    try {
      let result;
      switch (method) {
        case "tabs.list": {
          result = { tabs: await listAttachableTabs() };
          break;
        }
        case "tabs.create": {
          const tab = await chromeApi.tabs.create({
            url: typeof params.url === "string" && params.url.length > 0 ? params.url : "about:blank",
          });
          result = { tab: normalizeTab(tab) };
          break;
        }
        case "tabs.remove": {
          await chromeApi.tabs.remove(params.tabId);
          attachedTabs.delete(params.tabId);
          result = { ok: true };
          break;
        }
        case "tabs.activate": {
          const tab = await chromeApi.tabs.update(params.tabId, { active: true });
          if (tab && typeof tab.windowId === "number" && chromeApi.windows?.update) {
            await chromeApi.windows.update(tab.windowId, { focused: true }).catch(() => {});
          }
          result = { ok: true };
          break;
        }
        case "debugger.attach": {
          const tabId = params.tabId;
          await chromeApi.debugger.attach({ tabId }, "1.3");
          attachedTabs.add(tabId);
          result = { ok: true };
          break;
        }
        case "debugger.detach": {
          await detachTabSafe(params.tabId);
          result = { ok: true };
          break;
        }
        case "debugger.detachAll": {
          result = await detachAllTabs();
          break;
        }
        case "debugger.sendCommand": {
          const target = params.sessionId
            ? { tabId: params.tabId, sessionId: params.sessionId }
            : { tabId: params.tabId };
          result = await chromeApi.debugger.sendCommand(
            target,
            params.method,
            params.params ?? {},
          );
          if (params.method === "Page.bringToFront") {
            await chromeApi.tabs.update(params.tabId, { active: true }).catch(() => {});
          }
          break;
        }
        default: {
          throw new Error(`Unknown extension RPC method: ${method}`);
        }
      }
      postToBridge({ id, result: result ?? {} });
    } catch (err) {
      postToBridge({
        id,
        error: err?.message || String(err),
      });
    }
  }

  function handlePortMessage(message) {
    if (!message || typeof message !== "object") {
      return;
    }
    if (message.type === "bridge.status") {
      const nextConnected = Boolean(message.hostConnected);
      hostConnected = nextConnected;
      if (nextConnected) {
        lastError = null;
        void sendHello();
      } else {
        void detachAllTabs();
      }
      return;
    }
    if (message.type === "host.hello") {
      hostConnected = true;
      lastError = null;
      void sendHello();
      return;
    }
    if (message.id !== undefined && typeof message.method === "string") {
      void handleRpc(message.id, message.method, message.params);
    }
  }

  function scheduleReconnect() {
    if (reconnectTimer !== null) {
      return;
    }
    const delays = [1000, 2000, 5000, 10000, 20000, 30000];
    const delayMs = delays[Math.min(reconnectAttempt, delays.length - 1)];
    reconnectAttempt += 1;
    reconnectTimer = setTimeoutFn(() => {
      reconnectTimer = null;
      ensureConnected();
    }, delayMs);
  }

  function ensureConnected() {
    if (port) {
      return true;
    }
    if (reconnectTimer !== null) {
      clearTimeoutFn(reconnectTimer);
      reconnectTimer = null;
    }
    try {
      const nextPort = chromeApi.runtime.connectNative(NATIVE_HOST_NAME);
      port = nextPort;
      reconnectAttempt = 0;
      nextPort.onMessage.addListener(handlePortMessage);
      nextPort.onDisconnect.addListener(() => {
        const runtimeErr = chromeApi.runtime.lastError?.message;
        if (runtimeErr) {
          lastError = runtimeErr;
        }
        if (port === nextPort) {
          port = null;
          hostConnected = false;
        }
        void detachAllTabs();
        scheduleReconnect();
      });
      return true;
    } catch (err) {
      lastError = err?.message || String(err);
      port = null;
      hostConnected = false;
      scheduleReconnect();
      return false;
    }
  }

  function getStatus() {
    return {
      nativeConnected: port !== null,
      hostConnected,
      attachedTabCount: attachedTabs.size,
      attachedTabIds: Array.from(attachedTabs),
      extensionId: chromeApi.runtime.id || "",
      lastError,
    };
  }

  function registerListeners() {
    chromeApi.debugger.onEvent.addListener((source, method, params) => {
      emitEvent("chrome.debugger.onEvent", [source, method, params ?? {}]);
    });

    chromeApi.debugger.onDetach.addListener((source, reason) => {
      if (typeof source?.tabId === "number") {
        attachedTabs.delete(source.tabId);
      }
      emitEvent("chrome.debugger.onDetach", [source, reason]);
    });

    chromeApi.tabs.onCreated.addListener((tab) => {
      if (typeof tab?.id === "number" && isAttachableUrl(tab.url || tab.pendingUrl)) {
        emitEvent("chrome.tabs.onCreated", [normalizeTab(tab)]);
      }
    });

    chromeApi.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (typeof tabId === "number" && changeInfo?.url && isAttachableUrl(changeInfo.url)) {
        emitEvent("chrome.tabs.onUpdated", [normalizeTab({ ...tab, id: tabId, url: changeInfo.url })]);
      }
    });

    chromeApi.tabs.onRemoved.addListener((tabId) => {
      attachedTabs.delete(tabId);
      emitEvent("chrome.tabs.onRemoved", [tabId]);
    });

    chromeApi.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
      if (msg?.type === "styx.popup.getStatus") {
        ensureConnected();
        sendResponse(getStatus());
        return false;
      }
      if (msg?.type === "styx.popup.detachAll") {
        void detachAllTabs().then(() => sendResponse(getStatus()));
        return true;
      }
      if (msg?.type === "styx.popup.reconnect") {
        if (port) {
          try {
            port.disconnect();
          } catch {}
          port = null;
          hostConnected = false;
        }
        ensureConnected();
        sendResponse(getStatus());
        return false;
      }
      return false;
    });

    if (chromeApi.alarms?.create && chromeApi.alarms?.onAlarm) {
      chromeApi.alarms.create(KEEPALIVE_ALARM, { periodInMinutes: 1 });
      chromeApi.alarms.onAlarm.addListener((alarm) => {
        if (alarm?.name === KEEPALIVE_ALARM) {
          ensureConnected();
        }
      });
    }

    chromeApi.runtime.onInstalled?.addListener?.(() => {
      ensureConnected();
    });
    chromeApi.runtime.onStartup?.addListener?.(() => {
      ensureConnected();
    });
    chromeApi.tabs.onActivated?.addListener?.(() => {
      ensureConnected();
    });
  }

  return {
    ensureConnected,
    handlePortMessage,
    detachAllTabs,
    getStatus,
    registerListeners,
  };
}

if (typeof globalThis !== "undefined") {
  globalThis.__styxExtensionTools = {
    NATIVE_HOST_NAME,
    isAttachableUrl,
    parseBrowserVersion,
    createExtensionController,
  };
  if (globalThis.chrome?.runtime?.connectNative && globalThis.chrome?.debugger) {
    const controller = createExtensionController(globalThis.chrome);
    controller.registerListeners();
    controller.ensureConnected();
  }
}
