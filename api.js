// ================= VMS API ENGINE (DEVICE LOCK FINAL) =================

window.CLOUD_URL = "https://vms3modev4.sapammeded.workers.dev";

// ===== CORE REQUEST =====
async function request(path, method = "GET", body = null) {
    const token = (localStorage.getItem("token") || "").trim();
    const license = (localStorage.getItem("licenseKey") || "").trim();

    // 🔥 NO TOKEN → SHOW LOGIN UI
    if (!token) {
        console.warn("NO TOKEN → FORCE LOGIN");

        showLoginUI();
        throw new Error("NO_TOKEN");
    }

    try {
        const res = await fetch(`${window.CLOUD_URL}${path}`, {
            method,
            headers: {
                "Content-Type": "application/json",
                "x-token": token,
                "x-license": license,
                "x-device-id": getDeviceId() // 🔥 INI KUNCI UTAMA
            },
            body: body ? JSON.stringify(body) : null
        });

        let data;
        try {
            data = await res.json();
        } catch {
            throw new Error("INVALID_JSON");
        }

        // 🔥 HANDLE 401
        if (res.status === 401) {
            clearSession();
            showLoginUI();
            throw new Error("UNAUTHORIZED");
        }

        // 🔥 DEVICE ERROR HANDLER (INI BARU)
        if (res.status === 403) {
            const err = data?.error;

            if (err === "DEVICE_NOT_REGISTERED") {
                showToast("Device belum terdaftar", "warning");
            }

            if (err === "DEVICE_NOT_APPROVED") {
                showToast("Device belum di-approve admin", "warning");
            }

            throw new Error(err || "FORBIDDEN");
        }

        if (!res.ok) {
            throw new Error(data?.error || `HTTP_${res.status}`);
        }

        if (data && data.ok === false) {
            throw new Error(data.error || "API_FAILED");
        }

        return data?.data !== undefined ? data.data : data;

    } catch (err) {

        if (err.message === "NO_TOKEN") return;

        console.error("API ERROR:", path, err.message);
        throw err;
    }
}

// ===== SESSION =====
function clearSession() {
    localStorage.removeItem("token");
    localStorage.removeItem("username");
    localStorage.removeItem("role");
}

// ===== LOGIN UI =====
function showLoginUI() {
    const overlay = document.getElementById("loginOverlay");

    if (overlay && overlay.classList.contains("hidden")) {
        overlay.classList.remove("hidden");
    }

    const ids = ["topUsername", "sidebarUsername", "topRole", "sidebarRole"];
    ids.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerText = "-";
    });

    if (typeof showToast === "function") {
        showToast("Session expired / belum login", "warning");
    }
}

// ===== EXPORT =====
window.API = {
    call: request
};