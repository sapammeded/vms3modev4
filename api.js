// ================= CLEAN & STABLE API ENGINE (FINAL FIX) =================

window.CLOUD_URL = "https://vms3modev4.sapammeded.workers.dev";

// ===== SAFE REQUEST =====
async function request(path, method = "GET", body = null) {
    // 🔧 Ambil & bersihin token
    const cleanToken = (localStorage.getItem("token") || "").trim();
    const cleanLicense = (localStorage.getItem("licenseKey") || "").trim();

    // 🔴 STOP kalau gak ada token
    if (!cleanToken) {
        console.warn("NO TOKEN → STOP REQUEST:", path);
        throw new Error("NO_TOKEN");
    }

    try {
        // 🔥 Pakai Headers biar gak ke-split
        const headers = new Headers();
        headers.append("Content-Type", "application/json");
        headers.append("x-token", cleanToken);
        headers.append("x-license", cleanLicense);

        console.log("DEBUG TOKEN:", cleanToken); // opsional debug

        const res = await fetch(`${window.CLOUD_URL}${path}`, {
            method,
            headers: headers,
            body: body ? JSON.stringify(body) : null
        });

        let data;

        try {
            data = await res.json();
        } catch {
            throw new Error("INVALID_JSON");
        }

        // 🔴 HTTP error (401, 500, dll)
        if (!res.ok) {
            console.error("HTTP ERROR:", res.status, data);
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