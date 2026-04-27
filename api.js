// ================= VMS API ENGINE (FINAL PERFECT) =================

window.CLOUD_URL = "https://vms3modev4.sapammeded.workers.dev";

// ===== CORE REQUEST =====
async function request(path, method = "GET", body = null) {
    const token = (localStorage.getItem("token") || "").trim();
    const license = (localStorage.getItem("licenseKey") || "").trim();

    // 🔥 TOKEN KOSONG → FORCE LOGIN UI
    if (!token) {
        console.warn("NO TOKEN → FORCE LOGIN UI");

        const overlay = document.getElementById("loginOverlay");
        if (overlay && overlay.classList.contains("hidden")) {
            overlay.classList.remove("hidden");
        }

        throw new Error("NO_TOKEN");
    }

    try {
        const res = await fetch(`${window.CLOUD_URL}${path}`, {
            method,
            headers: {
                "Content-Type": "application/json",
                "x-token": token,
                "x-license": license
            },
            body: body ? JSON.stringify(body) : null
        });

        let data;
        try {
            data = await res.json();
        } catch {
            throw new Error("INVALID_JSON");
        }

        // 🔥 AUTO HANDLE 401 (SESSION EXPIRED)
        if (res.status === 401) {
            console.warn("401 → SESSION EXPIRED");

            clearSession();
            showLoginUI();

            throw new Error("UNAUTHORIZED");
        }

        // 🔴 HTTP ERROR
        if (!res.ok) {
            throw new Error(data?.error || `HTTP_${res.status}`);
        }

        // 🔴 API ERROR
        if (data && data.ok === false) {
            throw new Error(data.error || "API_FAILED");
        }

        // 🟢 NORMALIZE RESPONSE
        return data?.data !== undefined ? data.data : data;

    } catch (err) {

        // 🔥 NO_TOKEN → JANGAN SPAM ERROR (tapi tetap konsisten)
        if (err.message === "NO_TOKEN") {
            return Promise.reject(err);
        }

        console.error("API ERROR:", path, err.message);
        throw err;
    }
}

// ===== SESSION CONTROL =====
function clearSession() {
    localStorage.removeItem("token");
    localStorage.removeItem("username");
    localStorage.removeItem("role");
}

// ===== UI CONTROL =====
function showLoginUI() {
    const overlay = document.getElementById("loginOverlay");
    if (overlay && overlay.classList.contains("hidden")) {
        overlay.classList.remove("hidden");
    }

    // reset user display
    const ids = ["topUsername", "sidebarUsername", "topRole", "sidebarRole"];
    ids.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerText = "-";
    });

    // notif (kalau ada)
    if (typeof showToast === "function") {
        showToast("Session expired / belum login", "warning");
    }
}

// ===== PUBLIC API =====
window.API = {
    call: request
};