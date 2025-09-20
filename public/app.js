const publicVapidKey = "YOUR_PUBLIC_KEY";

// register service worker and subscribe
async function subscribeUser() {
  const register = await navigator.serviceWorker.register("/sw.js");

  const subscription = await register.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array(publicVapidKey)
  });

  // send subscription to backend
  await fetch("/subscribe", {
    method: "POST",
    body: JSON.stringify(subscription),
    headers: { "Content-Type": "application/json" }
  });
}

function urlBase64ToUint8Array(base64String) {
  const padding = "=".repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding).replace(/\-/g, "+").replace(/_/g, "/");
  const rawData = atob(base64);
  return Uint8Array.from([...rawData].map(char => char.charCodeAt(0)));
}

if ("serviceWorker" in navigator) {
  subscribeUser();
}
