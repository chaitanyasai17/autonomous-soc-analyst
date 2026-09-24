import axios from "axios";

const API_BASE_URL = (import.meta as any).env?.VITE_API_URL || "/api/v1";

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

// Attach access token to outgoing requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("asoc_access_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

let isRedirecting = false;

// Response error and notification handler
api.interceptors.response.use(
  (response) => {
    // Automatically dispatch badge refresh on successful alert or incident mutations
    const method = response.config?.method?.toLowerCase();
    const url = response.config?.url || "";
    if (
      (method === "post" || method === "patch" || method === "put" || method === "delete") &&
      (url.includes("/alerts") || url.includes("/incidents") || url.includes("/promote-to-alert"))
    ) {
      window.dispatchEvent(new CustomEvent("asoc:badges-refresh"));
    }
    return response;
  },
  (error) => {
    const status = error.response?.status;
    const requestUrl = error.config?.url || "";

    // Handle 401 Unauthorized for authenticated endpoints
    if (
      status === 401 &&
      !requestUrl.includes("/auth/login") &&
      !requestUrl.includes("/auth/register")
    ) {
      const token = localStorage.getItem("asoc_access_token");
      if (token) {
        localStorage.removeItem("asoc_access_token");
      }

      const currentPath = window.location.pathname;
      if (
        currentPath !== "/login" &&
        currentPath !== "/register" &&
        !isRedirecting
      ) {
        isRedirecting = true;
        window.dispatchEvent(new CustomEvent("asoc:unauthorized"));
        // Graceful redirect debounce
        setTimeout(() => {
          if (window.location.pathname !== "/login") {
            window.location.href = "/login";
          }
          isRedirecting = false;
        }, 150);
      }
    }
    return Promise.reject(error);
  }
);
