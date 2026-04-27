// ================= CLEAN & STABLE API ENGINE (FINAL NO-RELOAD VERSION) =================

window.CLOUD_URL = "https://vms3modev4.sapammeded.workers.dev";

// ===== SAFE REQUEST + AUTO 401 (NO RELOAD) =====
async function request(path, method = "GET", body = null) {
    const token = (localStorage.getItem("token") || "").trim();
    const license = (localStorage.getItem("licenseKey") || "").trim();

    // 🔴 STOP kalau belum login
    if (!token) {
        console.warn("NO TOKEN → STOP REQUEST:", path);
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

        // 🔥 AUTO HANDLE 401 (TANPA RELOAD)
        if (res.status === 401) {
            console.warn("401 DETECTED → AUTO LOGOUT (NO RELOAD)");

            // 🔥 bersihin session
            localStorage.removeItem("token");
            localStorage.removeItem("username");
            localStorage.removeItem("role");

            // 🔔 notifikasi
            if (typeof showToast === "function") {
                showToast("Session expired, silakan login ulang", "warning");
            } else {
                alert("Session expired, silakan login ulang");
            }

            // 🔥 tampilkan login overlay
            const overlay = document.getElementById("loginOverlay");
            if (overlay) overlay.classList.remove("hidden");

            // 🔥 reset UI user
            const ids = ["topUsername", "sidebarUsername", "topRole", "sidebarRole"];
            ids.forEach(id => {
                const el = document.getElementById(id);
                if (el) el.innerText = "-";
            });

            throw new Error("UNAUTHORIZED");
        }

        // 🔴 HTTP error lain
        if (!res.ok) {
            console.error("HTTP ERROR:", res.status, data);
            throw new Error(data?.error || `HTTP_${res.status}`);
        }

        // 🔴 API error
        if (data && data.ok === false) {
            throw new Error(data.error || "API_FAILED");
        }

        // 🟢 NORMALIZE RESPONSE
        return data?.data !== undefined ? data.data : data;

    } catch (err) {
        console.error("API ERROR:", path, err.message);
        throw err;
    }
}

// ===== PUBLIC API =====
window.API = {
    call: request
};
