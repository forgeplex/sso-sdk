import { UserManager, WebStorageStateStore } from "oidc-client-ts";
import "./style.css";

const output = element<HTMLPreElement>("output");
const fields = {
  issuer: element<HTMLInputElement>("issuer"),
  clientId: element<HTMLInputElement>("client-id"),
  audience: element<HTMLInputElement>("audience"),
  apiURL: element<HTMLInputElement>("api-url"),
};
const config = loadConfig();
fields.issuer.value = config.issuer;
fields.clientId.value = config.clientId;
fields.audience.value = config.audience;
fields.apiURL.value = config.apiURL;

element<HTMLButtonElement>("save-config").onclick = saveConfig;
element<HTMLButtonElement>("login").onclick = () => manager?.signinRedirect();
element<HTMLButtonElement>("logout").onclick = () => manager?.signoutRedirect();
element<HTMLButtonElement>("call-api").onclick = callAPI;

const manager = createManager(config);
if (manager) {
  await initialize(manager);
} else {
  element<HTMLButtonElement>("login").disabled = true;
  element<HTMLButtonElement>("logout").disabled = true;
  element<HTMLButtonElement>("call-api").disabled = true;
  output.textContent = "请填写 Issuer 和 Client ID，然后保存配置。";
}

async function initialize(userManager: UserManager) {
  try {
    if (window.location.pathname === "/callback") {
      await userManager.signinRedirectCallback();
      window.history.replaceState({}, document.title, "/");
    }
    if (window.location.pathname === "/logout-callback") {
      await userManager.signoutRedirectCallback();
      window.history.replaceState({}, document.title, "/");
    }
    const user = await userManager.getUser();
    output.textContent = user && !user.expired
      ? JSON.stringify({ profile: user.profile, expires_at: user.expires_at }, null, 2)
      : "尚未登录";
  } catch (error) {
    output.textContent = `登录处理失败：${formatError(error)}`;
  }
}

async function callAPI() {
  if (!config.apiURL) {
    output.textContent = "请先配置 API URL。";
    return;
  }
  if (!manager) {
    output.textContent = "请先保存 Issuer 和 Client ID。";
    return;
  }
  const user = await manager.getUser();
  if (!user || user.expired) {
    output.textContent = "请先登录";
    return;
  }
  try {
    const response = await fetch(config.apiURL, {
      headers: { Authorization: `Bearer ${user.access_token}` },
    });
    const body = await response.text();
    output.textContent = JSON.stringify({ status: response.status, body }, null, 2);
  } catch (error) {
    output.textContent = `API 调用失败：${formatError(error)}`;
  }
}

type Config = {
  issuer: string;
  clientId: string;
  audience: string;
  apiURL: string;
};

function loadConfig(): Config {
  let saved: Partial<Config> = {};
  try {
    saved = JSON.parse(window.sessionStorage.getItem("forgeplex-example-config") ?? "{}") as Partial<Config>;
  } catch {
    window.sessionStorage.removeItem("forgeplex-example-config");
  }
  return {
    issuer: import.meta.env.VITE_SSO_ISSUER?.trim() || saved.issuer || "",
    clientId: import.meta.env.VITE_SSO_CLIENT_ID?.trim() || saved.clientId || "",
    audience: import.meta.env.VITE_SSO_AUDIENCE?.trim() || saved.audience || "",
    apiURL: import.meta.env.VITE_API_URL?.trim() || saved.apiURL || "",
  };
}

function saveConfig() {
  const next: Config = {
    issuer: fields.issuer.value.trim(),
    clientId: fields.clientId.value.trim(),
    audience: fields.audience.value.trim(),
    apiURL: fields.apiURL.value.trim(),
  };
  if (!next.issuer || !next.clientId) {
    output.textContent = "Issuer 和 Client ID 为必填项。";
    return;
  }
  try {
    const issuerURL = new URL(next.issuer);
    if (issuerURL.protocol !== "http:" && issuerURL.protocol !== "https:") throw new Error();
  } catch {
    output.textContent = "Issuer 必须是有效的 HTTP(S) URL。";
    return;
  }
  window.sessionStorage.setItem("forgeplex-example-config", JSON.stringify(next));
  window.location.reload();
}

function createManager(settings: Config) {
  if (!settings.issuer || !settings.clientId) return undefined;
  return new UserManager({
    authority: settings.issuer,
    client_id: settings.clientId,
    redirect_uri: `${window.location.origin}/callback`,
    post_logout_redirect_uri: `${window.location.origin}/logout-callback`,
    response_type: "code",
    scope: "openid profile email",
    extraQueryParams: settings.audience ? { audience: settings.audience } : undefined,
    userStore: new WebStorageStateStore({ store: window.sessionStorage }),
    stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
  });
}

function element<T extends HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) throw new Error(`缺少页面元素 #${id}`);
  return value as T;
}

function formatError(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}
