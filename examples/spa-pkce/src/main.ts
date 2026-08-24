import { UserManager, WebStorageStateStore } from "oidc-client-ts";
import "./style.css";

const issuer = requiredEnv("VITE_SSO_ISSUER");
const clientId = requiredEnv("VITE_SSO_CLIENT_ID");
const audience = import.meta.env.VITE_SSO_AUDIENCE?.trim();
const apiURL = import.meta.env.VITE_API_URL?.trim();

const manager = new UserManager({
  authority: issuer,
  client_id: clientId,
  redirect_uri: `${window.location.origin}/callback`,
  post_logout_redirect_uri: `${window.location.origin}/logout-callback`,
  response_type: "code",
  scope: "openid profile email",
  extraQueryParams: audience ? { audience } : undefined,
  userStore: new WebStorageStateStore({ store: window.sessionStorage }),
  stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
});

const output = element<HTMLPreElement>("output");
element<HTMLButtonElement>("login").onclick = () => manager.signinRedirect();
element<HTMLButtonElement>("logout").onclick = () => manager.signoutRedirect();
element<HTMLButtonElement>("call-api").onclick = callAPI;

await initialize();

async function initialize() {
  try {
    if (window.location.pathname === "/callback") {
      await manager.signinRedirectCallback();
      window.history.replaceState({}, document.title, "/");
    }
    if (window.location.pathname === "/logout-callback") {
      await manager.signoutRedirectCallback();
      window.history.replaceState({}, document.title, "/");
    }
    const user = await manager.getUser();
    output.textContent = user && !user.expired
      ? JSON.stringify({ profile: user.profile, expires_at: user.expires_at }, null, 2)
      : "尚未登录";
  } catch (error) {
    output.textContent = `登录处理失败：${formatError(error)}`;
  }
}

async function callAPI() {
  if (!apiURL) {
    output.textContent = "请先配置 VITE_API_URL";
    return;
  }
  const user = await manager.getUser();
  if (!user || user.expired) {
    output.textContent = "请先登录";
    return;
  }
  try {
    const response = await fetch(apiURL, {
      headers: { Authorization: `Bearer ${user.access_token}` },
    });
    const body = await response.text();
    output.textContent = JSON.stringify({ status: response.status, body }, null, 2);
  } catch (error) {
    output.textContent = `API 调用失败：${formatError(error)}`;
  }
}

function requiredEnv(name: "VITE_SSO_ISSUER" | "VITE_SSO_CLIENT_ID") {
  const value = import.meta.env[name]?.trim();
  if (!value) throw new Error(`缺少环境变量 ${name}`);
  return value;
}

function element<T extends HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) throw new Error(`缺少页面元素 #${id}`);
  return value as T;
}

function formatError(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}
