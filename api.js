// ================= CLEAN & STABLE API ENGINE (FINAL FIX) =================

window.CLOUD_URL = "https://vms3modev4.sapammeded.workers.dev";

// ===== SAFE REQUEST =====
async function request(path, method = "GET", body = null) {
    const token = localStorage.getItem("token");
    const license = localStorage.getItem("licenseKey");

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
                "x-license": license || ""
            },
            body: body ? JSON.stringify(body) : null
        });

        let data;
        try {
            data = await res.json();
        } catch {
            throw new Error("INVALID_JSON");
        }

        // 🔴 HTTP error
        if (!res.ok) {
            throw new Error(data?.error || `HTTP_${res.status}`);
        }

        // 🔴 API error (format { ok:false })
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