// ================= CLEAN & STABLE API ENGINE (AUTO 401 FIX) =================

window.CLOUD_URL = "https://vms3modev4.sapammeded.workers.dev";

// ===== SAFE REQUEST + AUTO 401 =====
async function request(path, method = "GET", body = null) {
    const cleanToken = (localStorage.getItem("token") || "").trim();
    const cleanLicense = (localStorage.getItem("licenseKey") || "").trim();

    // 🔴 STOP kalau belum login
    if (!cleanToken) {
        console.warn("NO TOKEN → STOP REQUEST:", path);
        throw new Error("NO_TOKEN");
    }

    try {
        const headers = new Headers();
        headers.append("Content-Type", "application/json");
        headers.append("x-token", cleanToken);
        headers.append("x-license", cleanLicense);

        const res = await fetch(`${window.CLOUD_URL}${path}`, {
            method,
            headers,
            body: body ? JSON.stringify(body) : null
        });

        let data;
        try {
            data = await res.json();
        } catch {
            throw new Error("INVALID_JSON");
        }

        // 🔥 AUTO HANDLE 401 (INI YANG PALING PENTING)
        if (res.status === 401) {
            console.warn("401 DETECTED → AUTO LOGOUT");

            localStorage.removeItem("token");
            localStorage.removeItem("username");
            localStorage.removeItem("role");

            // pakai toast kalau ada
            if (typeof showToast === "function") {
                showToast("Session expired, silakan login ulang", "warning");
            } else {
                alert("Session expired, silakan login ulang");
            }

            setTimeout(() => {
                location.reload();
            }, 500);

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
        if (data && data.data !== undefined) {
            return data.data;
        }

        return data;

    } catch (err) {
        console.error("API ERROR:", path, err.message);
        throw err;
    }
}

// ===== PUBLIC API =====
window.API = {
    call: request
};
