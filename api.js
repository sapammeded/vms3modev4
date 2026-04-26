window.CLOUD_URL = "https://vms3modev4.sapammeded.workers.dev";

window.API = {
    async call(path, method = 'GET', body = null) {
        const token = localStorage.getItem('vms_admin_token');
        const license = localStorage.getItem('vms_license_key') || localStorage.getItem('vms_client_license');
        
        const finalLicense = license || localStorage.getItem('vms_client_license');

        const res = await fetch(`${this.CLOUD_URL}${path}`, {
            method,
            headers: {
                'Content-Type': 'application/json',
                'x-token': token || '',
                'x-license': finalLicense || ''
            },
            body: body ? JSON.stringify(body) : null
        });

        let data;
        try {
            data = await res.json();
        } catch {
            throw new Error('INVALID_JSON_RESPONSE');
        }

        if (!data.ok) {
            throw new Error(data.error || data.message || 'API_FAILED');
        }

        return data;
    }
};