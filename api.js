// ================= FINAL HARDENED API ENGINE =================

window.CLOUD_URL = "https://vms3modev4.sapammeded.workers.dev";

// ===== INTERNAL CONTROL =====
let ACTION_QUEUE = Promise.resolve();
let ACTION_LOCK = false;

// Queue (biar ga parallel)
function enqueue(fn) {
    ACTION_QUEUE = ACTION_QUEUE
        .then(() => fn())
        .catch(err => console.error("API ERROR:", err));

    return ACTION_QUEUE;
}

// Lock (anti spam klik / scan cepat)
async function guard(fn) {
    if (ACTION_LOCK) return;
    ACTION_LOCK = true;

    try {
        await fn();
    } finally {
        setTimeout(() => {
            ACTION_LOCK = false;
        }, 300);
    }
}

// RAW CALL (ini logic asli lo, jangan diubah)
async function rawCall(path, method, body) {
    const token = localStorage.getItem("token");
    const license = localStorage.getItem("licenseKey");

    const res = await fetch(`${window.CLOUD_URL}${path}`, {
        method,
        headers: {
            "Content-Type": "application/json",
            "x-token": token || "",
            "x-license": license || ""
        },
        body: body ? JSON.stringify(body) : null
    });

    let data;
    try {
        data = await res.json();
    } catch {
        throw new Error("INVALID_JSON_RESPONSE");
    }

    if (!data.ok) {
        throw new Error(data.error || data.message || "API_FAILED");
    }

    return data.data;
}

// ===== PUBLIC API =====
window.API = {
    async call(path, method = "GET", body = null) {

        // GET & LOGIN → langsung (biar ga delay UI)
        if (method === "GET" || path === "/login") {
            return rawCall(path, method, body);
        }

        // SEMUA WRITE → queue + lock
        return guard(() =>
            enqueue(() =>
                rawCall(path, method, body)
            )
        );
    }
};