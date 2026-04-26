// ================= CLEAN & STABLE API ENGINE =================

window.CLOUD_URL = "https://vms3modev4.sapammeded.workers.dev";

// ===== SIMPLE REQUEST =====
async function request(path, method = "GET", body = null) {
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
        throw new Error("INVALID_JSON");
    }

    if (!data.ok) {
        throw new Error(data.error || "API_FAILED");
    }

    return data.data;
}

// ===== PUBLIC API =====
window.API = {
    call: request
};