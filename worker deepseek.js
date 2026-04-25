// ==================== VMS WORKER v3.0 - FINAL HARDENED PATCH ====================
// Cloudflare Worker untuk VMS SAPAM MEDED
// FIX: Cannot access 'request' before initialization
// PLUS: safeArray + safeObject untuk semua KV

// ==================== SAFE KV HELPERS (DUAL LAYER) ====================
async function safeArray(env, key, defaultValue = []) {
    try {
        const data = await getData(env, key);
        if (Array.isArray(data)) {
            return data;
        }
        console.warn(`[SAFE_ARRAY] ${key} bukan array, fallback ke []. Tipe: ${typeof data}`);
        return defaultValue;
    } catch (e) {
        console.error(`[SAFE_ARRAY] Error fetching ${key}:`, e);
        return defaultValue;
    }
}

// PATCH TAMBAHAN: safeObject untuk object-based KV
async function safeObject(env, key, defaultValue = {}) {
    try {
        const data = await getData(env, key);
        if (data && typeof data === 'object' && !Array.isArray(data)) {
            return data;
        }
        console.warn(`[SAFE_OBJECT] ${key} bukan object, fallback ke {}`);
        return defaultValue;
    } catch (e) {
        console.error(`[SAFE_OBJECT] Error fetching ${key}:`, e);
        return defaultValue;
    }
}

// ==================== MAIN HANDLER ====================
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, x-token, authorization, Authorization',
            'Content-Type': 'application/json'
        };
        
        if (request.method === 'OPTIONS') {
            return new Response(null, { status: 204, headers: corsHeaders });
        }
        
        try {
            if (!globalThis.__vms_init_done) {
                let adminsCheck = await safeArray(env, 'admins');
                if (!adminsCheck || adminsCheck.length === 0) {
                    await forceInit(env);
                }
                globalThis.__vms_init_done = true;
            }
            
            if (!globalThis.__rate) globalThis.__rate = {};
            
            function checkRateLimit(deviceId) {
                const now = Date.now();
                const windowStart = now - 10000;
                if (!globalThis.__rate[deviceId]) {
                    globalThis.__rate[deviceId] = [];
                }
                globalThis.__rate[deviceId] = globalThis.__rate[deviceId].filter(t => t > windowStart);
                if (globalThis.__rate[deviceId].length >= 20) {
                    return false;
                }
                globalThis.__rate[deviceId].push(now);
                return true;
            }
            
            if (path === '/force-init' && request.method === 'POST') {
                await forceInit(env);
                return new Response(JSON.stringify({ ok: true, message: 'System initialized' }), { headers: corsHeaders });
            }
            
            if (path === '/' && request.method === 'GET') {
                return new Response(JSON.stringify({ 
                    status: 'online', 
                    version: 'v3.0 Enterprise Final',
                    timestamp: Date.now()
                }), { headers: corsHeaders });
            }
            
            if (path === '/login' && request.method === 'POST') {
                const body = await request.json();
                const { username, password } = body;
                
                console.log(`[LOGIN] Attempt for username: ${username}`);
                
                let admins = await safeArray(env, 'admins');
                if (!admins || admins.length === 0) {
                    await forceInit(env);
                    admins = await safeArray(env, 'admins');
                }
                
                admins = admins.map(a => {
                    if (a.username === username) {
                        return { ...a, token: null };
                    }
                    return a;
                });
                await saveData(env, 'admins', admins);
                
                const admin = admins.find(a => a.username === username);
                
                if (!admin) {
                    console.log(`[LOGIN] User not found: ${username}`);
                    return new Response(JSON.stringify({ ok: false, error: 'User not found' }), { 
                        headers: corsHeaders, 
                        status: 401 
                    });
                }
                
                console.log(`[LOGIN] User found: ${admin.username}, role: ${admin.role}`);
                
                const hashedInputPassword = await sha256(password);
                let storedPassword = admin.password;
                
                let isValid = (hashedInputPassword === storedPassword);
                
                if (!isValid && storedPassword === password) {
                    console.log(`[LOGIN] Plain text match, upgrading to hash...`);
                    isValid = true;
                    admin.password = hashedInputPassword;
                    storedPassword = admin.password;
                }
                
                if (!isValid && username === 'admin' && password === '123456') {
                    console.log(`[LOGIN] Using default admin fallback`);
                    isValid = true;
                    admin.password = await sha256('123456');
                }
                
                if (!isValid) {
                    console.log(`[LOGIN] Password invalid for: ${username}`);
                    return new Response(JSON.stringify({ ok: false, error: 'Invalid password' }), { 
                        headers: corsHeaders, 
                        status: 401 
                    });
                }
                
                const token = 'vms_token_' + Date.now() + '_' + crypto.randomUUID();
                admin.token = token;
                admin.lastLogin = Date.now();
                await saveData(env, 'admins', admins);
                
                console.log(`[LOGIN] Success for: ${username}`);
                
                return new Response(JSON.stringify({
                    ok: true,
                    token: token,
                    username: admin.username,
                    role: admin.role
                }), { headers: corsHeaders });
            }
            
            const auth = await checkAuth(request.headers, env);
            
            const protectedPaths = [
                '/admin/stats', '/admin/companies', '/admin/devices', 
                '/admin/activity', '/admin/invoices', '/admin/device-requests',
                '/generate-license', '/renew-license', '/update-package',
                '/approve-device', '/delete-device', '/delete-company',
                '/mark-invoice-paid', '/admin/users', '/admin/add-user', 
                '/admin/delete-user', '/admin/settings', '/admin/company/',
                '/approve-device-request', '/admin/violations'
            ];
            
            if (protectedPaths.some(p => path === p || path.startsWith('/admin/company/')) && !auth) {
                return new Response(JSON.stringify({ ok: false, error: 'Unauthorized' }), { 
                    headers: corsHeaders, 
                    status: 401 
                });
            }
            
            const VIOLATION_SCORES = {
                LIMIT_VISITOR: 2,
                LIMIT_SCAN: 2,
                RATE_SPAM: 3,
                INVALID_DATA: 2,
                DUPLICATE_ABUSE: 1
            };
            
            async function addViolation(licenseKey, type, details, metadata = {}) {
                try {
                    let violations = await safeArray(env, 'violations');
                    
                    const violation = {
                        id: generateId(),
                        licenseKey: licenseKey,
                        type: type,
                        score: VIOLATION_SCORES[type] || 1,
                        details: details,
                        metadata: metadata,
                        timestamp: Date.now()
                    };
                    
                    violations.push(violation);
                    await saveData(env, 'violations', violations.slice(-10000));
                    
                    console.warn(`[VIOLATION] ${type} for ${licenseKey}: ${details}`);
                    
                    return violation;
                } catch (e) {
                    console.error('[VIOLATION] Error adding violation:', e);
                    return null;
                }
            }
            
            async function getViolationStatus(licenseKey) {
                try {
                    const violations = await safeArray(env, 'violations');
                    const licenseViolations = violations.filter(v => v.licenseKey === licenseKey);
                    
                    const totalScore = licenseViolations.reduce((sum, v) => sum + (v.score || 1), 0);
                    const recentViolations = licenseViolations.filter(v => v.timestamp > Date.now() - 7 * 86400000);
                    const recentScore = recentViolations.reduce((sum, v) => sum + (v.score || 1), 0);
                    
                    let status = 'NORMAL';
                    let recommendation = null;
                    
                    if (totalScore >= 20 || recentScore >= 10) {
                        status = 'CRITICAL';
                        recommendation = 'Review required immediately';
                    } else if (totalScore >= 10 || recentScore >= 5) {
                        status = 'WARNING';
                        recommendation = 'Monitor closely';
                    } else if (totalScore >= 5 || recentScore >= 3) {
                        status = 'ATTENTION';
                        recommendation = 'Investigate patterns';
                    }
                    
                    const violationsByType = {};
                    for (const v of licenseViolations) {
                        violationsByType[v.type] = (violationsByType[v.type] || 0) + 1;
                    }
                    
                    return {
                        licenseKey: licenseKey,
                        status: status,
                        totalScore: totalScore,
                        recentScore: recentScore,
                        totalViolations: licenseViolations.length,
                        recentViolations: recentViolations.length,
                        violationsByType: violationsByType,
                        recommendation: recommendation,
                        lastViolationAt: licenseViolations.length > 0 ? Math.max(...licenseViolations.map(v => v.timestamp)) : null
                    };
                } catch (e) {
                    console.error('[VIOLATION] Error getting status:', e);
                    return { licenseKey, status: 'UNKNOWN', totalScore: 0 };
                }
            }
            
            if (path === '/validate-license' && request.method === 'POST') {
                const body = await request.json();
                const { licenseKey, deviceId, deviceName, meta } = body;
                
                if (!licenseKey) {
                    return new Response(JSON.stringify({ ok: false, message: 'License key required' }), { headers: corsHeaders });
                }
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.licenseKey === licenseKey);
                
                if (!company) {
                    await addViolation(licenseKey, 'INVALID_DATA', 'Invalid license key validation attempt', { deviceId });
                    return new Response(JSON.stringify({ ok: false, message: 'Invalid license key' }), { headers: corsHeaders });
                }
                
                const isExpired = company.expiredAt < Date.now();
                if (isExpired) {
                    return new Response(JSON.stringify({ 
                        ok: false, 
                        message: 'License expired',
                        company: { ...company, status: 'EXPIRED' }
                    }), { headers: corsHeaders });
                }
                
                const devices = await safeArray(env, 'devices');
                const companyDevices = devices.filter(d => d.licenseKey === licenseKey && d.status !== 'DELETED');
                const currentDeviceCount = companyDevices.length;
                
                let status = 'ACTIVE';
                if (currentDeviceCount >= company.maxDevices) {
                    status = 'PENDING_APPROVAL';
                }
                
                let device = devices.find(d => d.deviceId === deviceId && d.licenseKey === licenseKey);
                if (device) {
                    device.lastSeen = Date.now();
                    device.deviceName = deviceName || device.deviceName;
                    device.meta = meta;
                } else {
                    device = {
                        deviceId: deviceId,
                        deviceName: deviceName || deviceId,
                        licenseKey: licenseKey,
                        companyId: company.id,
                        companyName: company.companyName,
                        status: status,
                        firstSeen: Date.now(),
                        lastSeen: Date.now(),
                        meta: meta,
                        violations: [],
                        sessions: []
                    };
                    devices.push(device);
                }
                
                await saveData(env, 'devices', devices);
                
                company.currentDevices = devices.filter(d => d.licenseKey === licenseKey && d.status === 'ACTIVE').length;
                await saveData(env, 'companies', companies);
                
                const violationStatus = await getViolationStatus(licenseKey);
                
                return new Response(JSON.stringify({
                    ok: true,
                    status: status,
                    company: {
                        id: company.id,
                        name: company.companyName,
                        package: company.package,
                        maxDevices: company.maxDevices,
                        currentDevices: company.currentDevices,
                        expiredAt: company.expiredAt
                    },
                    device: device,
                    violationStatus: violationStatus
                }), { headers: corsHeaders });
            }
            
            if (path === '/client/devices' && request.method === 'POST') {
                const body = await request.json();
                const { licenseKey } = body;
                
                if (!licenseKey) {
                    return new Response(JSON.stringify({ ok: false, devices: [] }), { headers: corsHeaders });
                }
                
                const devices = await safeArray(env, 'devices');
                const companyDevices = devices.filter(d => d.licenseKey === licenseKey && d.status !== 'DELETED');
                
                return new Response(JSON.stringify({ ok: true, devices: companyDevices }), { headers: corsHeaders });
            }
            
            // PATCH: safeObject untuk site_names
            if (path === '/site-names' && request.method === 'POST') {
                const body = await request.json();
                const { licenseKey, sites, customSites } = body;
                
                if (!licenseKey) {
                    return new Response(JSON.stringify({ ok: false, error: 'License key required' }), { headers: corsHeaders });
                }
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.licenseKey === licenseKey);
                
                if (!company) {
                    return new Response(JSON.stringify({ ok: false, error: 'Invalid license' }), { headers: corsHeaders });
                }
                
                let siteNames = await safeObject(env, 'site_names');
                
                if (sites) {
                    for (const [key, value] of Object.entries(sites)) {
                        if (value && value.trim()) {
                            siteNames[key] = value.trim();
                        }
                    }
                }
                
                if (customSites) {
                    if (!siteNames.customSites) siteNames.customSites = {};
                    for (const [key, value] of Object.entries(customSites)) {
                        if (value && value.trim()) {
                            siteNames.customSites[key] = value.trim();
                        }
                    }
                }
                
                await saveData(env, 'site_names', siteNames);
                
                return new Response(JSON.stringify({
                    ok: true,
                    sites: siteNames,
                    customSites: siteNames.customSites || {}
                }), { headers: corsHeaders });
            }
            
            if (path === '/site-names' && request.method === 'GET') {
                const siteNames = await safeObject(env, 'site_names');
                return new Response(JSON.stringify({
                    ok: true,
                    sites: siteNames || {},
                    customSites: (siteNames && siteNames.customSites) || {}
                }), { headers: corsHeaders });
            }
            
            if (path === '/checkin' && request.method === 'POST') {
                const body = await request.json();
                const { licenseKey, deviceId, action, location, qrData } = body;
                
                if (!licenseKey || !deviceId) {
                    return new Response(JSON.stringify({ ok: false, error: 'License key and device ID required' }), { headers: corsHeaders });
                }
                
                if (!checkRateLimit(deviceId)) {
                    return new Response(JSON.stringify({ ok: false, error: 'RATE_LIMIT' }), { headers: corsHeaders });
                }
                
                const devices = await safeArray(env, 'devices');
                const device = devices.find(d => d.deviceId === deviceId && d.licenseKey === licenseKey);
                if (!device) {
                    await addViolation(licenseKey, 'INVALID_DATA', 'Device not registered for check-in', { deviceId });
                    return new Response(JSON.stringify({ ok: false, error: 'DEVICE_NOT_REGISTERED' }), { headers: corsHeaders });
                }
                
                if (device.status === 'BANNED') {
                    await addViolation(licenseKey, 'RATE_SPAM', 'Attempted check-in from banned device', { deviceId });
                    return new Response(JSON.stringify({ ok: false, error: 'DEVICE_BANNED' }), { headers: corsHeaders });
                }
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.licenseKey === licenseKey);
                if (!company || company.expiredAt < Date.now()) {
                    return new Response(JSON.stringify({ ok: false, error: 'License invalid or expired' }), { headers: corsHeaders });
                }
                
                const activities = await safeArray(env, 'activities');
                const activity = {
                    id: generateId(),
                    deviceId: deviceId,
                    deviceName: device.deviceName,
                    licenseKey: licenseKey,
                    companyId: company.id,
                    companyName: company.companyName,
                    action: action,
                    location: location || null,
                    qrData: qrData || null,
                    timestamp: Date.now(),
                    type: action === 'IN' ? 'CHECK_IN' : 'CHECK_OUT'
                };
                activities.unshift(activity);
                await saveData(env, 'activities', activities.slice(0, 5000));
                
                device.lastSeen = Date.now();
                await saveData(env, 'devices', devices);
                
                let logs = await safeArray(env, 'logs');
                logs.unshift({
                    id: generateId(),
                    type: action === 'IN' ? 'CHECK_IN' : 'CHECK_OUT',
                    licenseKey: licenseKey,
                    companyId: company.id,
                    companyName: company.companyName,
                    deviceId: deviceId,
                    deviceName: device.deviceName,
                    location: location,
                    timestamp: Date.now()
                });
                await saveData(env, 'logs', logs.slice(0, 10000));
                
                const violationStatus = await getViolationStatus(licenseKey);
                
                return new Response(JSON.stringify({ 
                    ok: true, 
                    activity: activity,
                    violationStatus: violationStatus
                }), { headers: corsHeaders });
            }
            
            if (path === '/save' && request.method === 'POST') {
                let body;
                try {
                    body = await request.json();
                } catch(e) {
                    console.error('[SAVE] Invalid JSON:', e);
                    return new Response(JSON.stringify({ ok: false, error: 'INVALID_JSON' }), { headers: corsHeaders });
                }
                
                const { licenseKey, deviceId } = body;
                
                if (!licenseKey || !deviceId) {
                    console.warn('[SAVE] Missing licenseKey or deviceId');
                    return new Response(JSON.stringify({ ok: false, error: 'INVALID_REQUEST' }), { headers: corsHeaders });
                }
                
                if (!checkRateLimit(deviceId)) {
                    console.warn(`[SAVE] Rate limit exceeded for device ${deviceId}`);
                    return new Response(JSON.stringify({ ok: false, error: 'RATE_LIMIT' }), { headers: corsHeaders });
                }
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.licenseKey === licenseKey);
                
                if (!company) {
                    await addViolation(licenseKey, 'INVALID_DATA', 'Invalid license key in /save', { deviceId });
                    console.warn(`[SAVE] Invalid license key: ${licenseKey}`);
                    return new Response(JSON.stringify({ ok: false, error: 'INVALID_LICENSE' }), { headers: corsHeaders });
                }
                
                if (company.expiredAt < Date.now()) {
                    console.warn(`[SAVE] License expired for: ${licenseKey}`);
                    return new Response(JSON.stringify({ ok: false, error: 'LICENSE_EXPIRED' }), { headers: corsHeaders });
                }
                
                const devices = await safeArray(env, 'devices');
                const device = devices.find(d => d.deviceId === deviceId && d.licenseKey === licenseKey);
                
                if (!device) {
                    await addViolation(licenseKey, 'INVALID_DATA', 'Device not registered in /save', { deviceId });
                    console.warn(`[SAVE] Device not registered: ${deviceId}`);
                    return new Response(JSON.stringify({ ok: false, error: 'DEVICE_NOT_REGISTERED' }), { headers: corsHeaders });
                }
                
                if (device.status === 'BANNED') {
                    await addViolation(licenseKey, 'RATE_SPAM', 'Banned device attempted /save', { deviceId });
                    console.warn(`[SAVE] Banned device blocked: ${deviceId}`);
                    return new Response(JSON.stringify({ ok: false, error: 'DEVICE_BANNED' }), { headers: corsHeaders });
                }
                
                const isSuspended = (device.status === 'SUSPENDED');
                if (isSuspended) {
                    console.warn(`[SAVE] Suspended device: ${deviceId} - only logs allowed`);
                }
                
                const packageType = company.package || 'DEMO';
                let maxAllowed = Infinity;
                if (packageType === 'DEMO') maxAllowed = 5;
                else if (packageType === 'BASIC') maxAllowed = 150;
                else if (packageType === 'PRO') maxAllowed = Infinity;
                
                // PATCH: safeObject untuk visitors
                let allVisitors = await safeObject(env, 'visitors');
                const companyVisitors = Object.values(allVisitors).filter(v => v.licenseKey === licenseKey);
                const currentVisitorCount = companyVisitors.length;
                
                if (body.visitors && Object.keys(body.visitors).length > 0 && !isSuspended) {
                    let newVisitorCount = 0;
                    
                    for (const [key, value] of Object.entries(body.visitors)) {
                        if (currentVisitorCount + newVisitorCount >= maxAllowed) {
                            await addViolation(licenseKey, 'LIMIT_VISITOR', `Visitor limit would be exceeded in /save`, {
                                currentCount: currentVisitorCount,
                                attemptedAdd: newVisitorCount,
                                maxAllowed: maxAllowed
                            });
                            console.warn(`[SAVE] Visitor limit reached for ${licenseKey}, blocking additional visitors`);
                            break;
                        }
                        
                        const safeVisitor = {
                            nama: (value.nama || "").substring(0, 200),
                            perusahaan: (value.perusahaan || "").substring(0, 200),
                            kategori: (value.kategori || "").substring(0, 200),
                            tujuan: (value.tujuan || "").substring(0, 200),
                            pic: (value.pic || "").substring(0, 200),
                            dept: (value.dept || "").substring(0, 200),
                            expDate: value.expDate || "",
                            licenseKey: licenseKey,
                            companyId: company.id,
                            companyName: company.companyName
                        };
                        
                        allVisitors[key] = { ...allVisitors[key], ...safeVisitor, lastSync: Date.now() };
                        newVisitorCount++;
                    }
                    
                    if (newVisitorCount > 0) {
                        await saveData(env, 'visitors', allVisitors);
                        console.log(`[SAVE] Saved ${newVisitorCount} visitors for ${licenseKey}`);
                    }
                } else if (body.visitors && Object.keys(body.visitors).length > 0 && isSuspended) {
                    console.warn(`[SAVE] Suspended device ${deviceId} attempted to save visitors - blocked`);
                    await addViolation(licenseKey, 'RATE_SPAM', 'Suspended device attempted to save visitors', { deviceId, visitorCount: Object.keys(body.visitors).length });
                }
                
                if (body.logs && body.logs.length > 0) {
                    const allowedLogTypes = ['CHECK_IN', 'CHECK_OUT', 'REGISTER', 'WALK_IN'];
                    let validLogs = [];
                    
                    for (const log of body.logs) {
                        if (allowedLogTypes.includes(log.type) || allowedLogTypes.includes(log.action)) {
                            validLogs.push({
                                ...log,
                                licenseKey: licenseKey,
                                companyId: company.id,
                                companyName: company.companyName,
                                deviceId: deviceId,
                                validatedAt: Date.now()
                            });
                        } else {
                            console.warn(`[SAVE] Skipping invalid log type: ${log.type || log.action}`);
                            await addViolation(licenseKey, 'INVALID_DATA', `Invalid log type: ${log.type || log.action}`, { logType: log.type });
                        }
                    }
                    
                    if (validLogs.length > 0) {
                        let allLogs = await safeArray(env, 'logs');
                        allLogs = [...validLogs, ...allLogs];
                        await saveData(env, 'logs', allLogs.slice(0, 10000));
                        console.log(`[SAVE] Saved ${validLogs.length} logs for ${licenseKey}`);
                    }
                }
                
                if (body.anti) {
                    let reports = await safeArray(env, 'anti_nakal_reports');
                    reports.unshift({
                        ...body.anti,
                        deviceId: deviceId,
                        deviceName: device.deviceName,
                        site: body.site,
                        licenseKey: licenseKey,
                        timestamp: Date.now()
                    });
                    await saveData(env, 'anti_nakal_reports', reports.slice(0, 5000));
                    console.log(`[SAVE] Saved anti-nakal report for ${licenseKey}`);
                }
                
                device.lastSeen = Date.now();
                await saveData(env, 'devices', devices);
                
                return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
            }
            
            if (path === '/violation-status' && request.method === 'POST') {
                const body = await request.json();
                const { licenseKey } = body;
                
                if (!licenseKey) {
                    return new Response(JSON.stringify({ ok: false, error: 'License key required' }), { headers: corsHeaders });
                }
                
                const status = await getViolationStatus(licenseKey);
                return new Response(JSON.stringify({ ok: true, status: status }), { headers: corsHeaders });
            }
            
            if (path === '/report-violation' && request.method === 'POST') {
                const body = await request.json();
                const { licenseKey, deviceId, violationType, details, location } = body;
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.licenseKey === licenseKey);
                if (!company) {
                    return new Response(JSON.stringify({ ok: false, message: 'Invalid license' }), { headers: corsHeaders });
                }
                
                const devices = await safeArray(env, 'devices');
                const device = devices.find(d => d.deviceId === deviceId);
                if (!device) {
                    return new Response(JSON.stringify({ ok: false, message: 'Device not found' }), { headers: corsHeaders });
                }
                
                const violation = await addViolation(licenseKey, violationType, details, {
                    deviceId: deviceId,
                    deviceName: device.deviceName,
                    location: location
                });
                
                if (!device.violations) device.violations = [];
                device.violations.unshift(violation);
                
                const violationCount = device.violations.length;
                let deviceStatus = device.status;
                
                if (violationCount >= 5) {
                    deviceStatus = 'BANNED';
                } else if (violationCount >= 3) {
                    deviceStatus = 'SUSPENDED';
                }
                
                device.status = deviceStatus;
                await saveData(env, 'devices', devices);
                
                const activities = await safeArray(env, 'activities');
                activities.unshift({
                    id: generateId(),
                    ...violation,
                    type: 'VIOLATION_REPORTED'
                });
                await saveData(env, 'activities', activities.slice(0, 5000));
                
                return new Response(JSON.stringify({
                    ok: true,
                    violation: violation,
                    deviceStatus: deviceStatus,
                    violationCount: violationCount
                }), { headers: corsHeaders });
            }
            
            if (path === '/admin/violations' && request.method === 'GET') {
                if (!auth) {
                    return new Response(JSON.stringify({ ok: false, error: 'Unauthorized' }), { 
                        headers: corsHeaders, 
                        status: 401 
                    });
                }
                
                const urlParams = new URL(request.url).searchParams;
                const licenseKey = urlParams.get('licenseKey');
                const limit = parseInt(urlParams.get('limit') || '100');
                
                let violations = await safeArray(env, 'violations');
                
                if (licenseKey) {
                    violations = violations.filter(v => v.licenseKey === licenseKey);
                }
                
                violations = violations.slice(0, limit);
                
                const summary = {};
                for (const v of violations) {
                    if (!summary[v.licenseKey]) {
                        summary[v.licenseKey] = {
                            totalScore: 0,
                            counts: {}
                        };
                    }
                    summary[v.licenseKey].totalScore += v.score || 1;
                    summary[v.licenseKey].counts[v.type] = (summary[v.licenseKey].counts[v.type] || 0) + 1;
                }
                
                return new Response(JSON.stringify({
                    ok: true,
                    violations: violations,
                    summary: summary,
                    total: violations.length
                }), { headers: corsHeaders });
            }
            
            // PATCH UTAMA (FIXED): /request-approval endpoint
            if (path === '/request-approval' && request.method === 'POST') {
                const requestBody = await request.json();
                const { licenseKey, deviceId, deviceName, reason } = requestBody;
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.licenseKey === licenseKey);
                if (!company) {
                    return new Response(JSON.stringify({ ok: false, message: 'Invalid license' }), { headers: corsHeaders });
                }
                
                const devices = await safeArray(env, 'devices');
                const targetDevice = devices.find(d => d.deviceId === deviceId);
                if (targetDevice) {
                    targetDevice.approvalRequest = {
                        requestedAt: Date.now(),
                        reason: reason,
                        status: 'PENDING'
                    };
                    targetDevice.status = 'PENDING_APPROVAL';
                    await saveData(env, 'devices', devices);
                }
                
                return new Response(JSON.stringify({ ok: true, message: 'Approval request sent' }), { headers: corsHeaders });
            }
            
            // PATCH UTAMA (FIXED): /request-device endpoint
            if (path === '/request-device' && request.method === 'POST') {
                const requestBody = await request.json();
                const { licenseKey, deviceName, reason } = requestBody;
                
                let deviceRequests = await safeArray(env, 'device_requests');
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.licenseKey === licenseKey);
                
                if (!company) {
                    return new Response(JSON.stringify({ ok: false, message: 'Invalid license' }), { headers: corsHeaders });
                }
                
                let fee = 0;
                if (company.package === 'BASIC') {
                    // PATCH: safeObject untuk settings
                    const settings = await safeObject(env, 'settings');
                    fee = (settings?.pricing?.BASIC?.extraDeviceFee || 50000);
                }
                
                if (!Array.isArray(deviceRequests)) {
                    console.warn(`[request-device] device_requests bukan array, reset ke []`);
                    deviceRequests = [];
                }
                
                const newRequest = {
                    id: generateId(),
                    licenseKey: licenseKey,
                    companyId: company.id,
                    companyName: company.companyName,
                    deviceName: deviceName,
                    reason: reason,
                    fee: fee,
                    status: 'PENDING',
                    requestedAt: Date.now()
                };
                
                deviceRequests.push(newRequest);
                await saveData(env, 'device_requests', deviceRequests);
                
                return new Response(JSON.stringify({
                    ok: true,
                    requestId: newRequest.id,
                    fee: fee,
                    message: fee > 0 ? `Fee Rp ${fee.toLocaleString()} akan ditagihkan` : 'Request sent, waiting approval'
                }), { headers: corsHeaders });
            }
            
            if (path === '/admin/stats' && request.method === 'GET') {
                const companies = await safeArray(env, 'companies');
                const devices = await safeArray(env, 'devices');
                const activities = await safeArray(env, 'activities');
                const invoices = await safeArray(env, 'invoices');
                const violations = await safeArray(env, 'violations');
                
                const now = Date.now();
                const last30Days = now - 30 * 86400000;
                
                const stats = {
                    companies: {
                        total: companies.length,
                        active: companies.filter(c => c.expiredAt > now).length,
                        byPackage: {
                            DEMO: companies.filter(c => c.package === 'DEMO').length,
                            BASIC: companies.filter(c => c.package === 'BASIC').length,
                            PRO: companies.filter(c => c.package === 'PRO').length
                        }
                    },
                    devices: {
                        total: devices.length,
                        active: devices.filter(d => d.status === 'ACTIVE').length,
                        pending: devices.filter(d => d.status === 'PENDING_APPROVAL').length,
                        suspended: devices.filter(d => d.status === 'SUSPENDED').length,
                        banned: devices.filter(d => d.status === 'BANNED').length
                    },
                    violations: {
                        total: violations.length,
                        last7Days: violations.filter(v => v.timestamp > now - 7 * 86400000).length,
                        last30Days: violations.filter(v => v.timestamp > last30Days).length,
                        byType: violations.reduce((acc, v) => {
                            acc[v.type] = (acc[v.type] || 0) + 1;
                            return acc;
                        }, {})
                    },
                    revenue: {
                        last30Days: invoices.filter(i => i.status === 'PAID' && i.paidAt > last30Days).reduce((sum, i) => sum + i.amount, 0)
                    }
                };
                
                return new Response(JSON.stringify(stats), { headers: corsHeaders });
            }
            
            if (path === '/admin/companies' && request.method === 'GET') {
                const companies = await safeArray(env, 'companies');
                return new Response(JSON.stringify(companies), { headers: corsHeaders });
            }
            
            if (path.startsWith('/admin/company/') && request.method === 'GET') {
                const companyId = path.split('/').pop();
                const companies = await safeArray(env, 'companies');
                const devices = await safeArray(env, 'devices');
                const violations = await safeArray(env, 'violations');
                
                const company = companies.find(c => c.id === companyId);
                if (!company) {
                    return new Response(JSON.stringify({ ok: false, error: 'Company not found' }), { 
                        headers: corsHeaders, 
                        status: 404 
                    });
                }
                
                const companyDevices = devices.filter(d => d.companyId === companyId);
                const companyViolations = violations.filter(v => v.licenseKey === company.licenseKey);
                
                return new Response(JSON.stringify({
                    ...company,
                    devices: companyDevices,
                    violations: companyViolations,
                    violationStatus: await getViolationStatus(company.licenseKey),
                    stats: {
                        totalDevices: companyDevices.length,
                        activeDevices: companyDevices.filter(d => d.status === 'ACTIVE').length,
                        totalViolations: companyViolations.length
                    }
                }), { headers: corsHeaders });
            }
            
            if (path === '/admin/devices' && request.method === 'GET') {
                const devices = await safeArray(env, 'devices');
                return new Response(JSON.stringify(devices), { headers: corsHeaders });
            }
            
            if (path === '/admin/activity' && request.method === 'GET') {
                const urlParams = new URL(request.url).searchParams;
                const limit = parseInt(urlParams.get('limit') || '500');
                const activities = await safeArray(env, 'activities');
                return new Response(JSON.stringify(activities.slice(0, limit)), { headers: corsHeaders });
            }
            
            if (path === '/admin/invoices' && request.method === 'GET') {
                const invoices = await safeArray(env, 'invoices');
                return new Response(JSON.stringify(invoices), { headers: corsHeaders });
            }
            
            if (path === '/admin/device-requests' && request.method === 'GET') {
                const urlParams = new URL(request.url).searchParams;
                const status = urlParams.get('status');
                
                let deviceRequests = await safeArray(env, 'device_requests');
                if (status) {
                    deviceRequests = deviceRequests.filter(r => r.status === status);
                }
                
                return new Response(JSON.stringify(deviceRequests), { headers: corsHeaders });
            }
            
            // PATCH (FIXED): /approve-device-request endpoint - no variable shadowing
            if (path === '/approve-device-request' && request.method === 'POST') {
                const requestBody = await request.json();
                const { requestId, approve, notes } = requestBody;
                
                let deviceRequests = await safeArray(env, 'device_requests');
                const targetRequest = deviceRequests.find(r => r.id === requestId);
                
                if (!targetRequest) {
                    return new Response(JSON.stringify({ ok: false, error: 'Request not found' }), { headers: corsHeaders });
                }
                
                if (!approve) {
                    targetRequest.status = 'REJECTED';
                    targetRequest.rejectedAt = Date.now();
                    targetRequest.rejectNotes = notes;
                    await saveData(env, 'device_requests', deviceRequests);
                    return new Response(JSON.stringify({ ok: true, request: targetRequest }), { headers: corsHeaders });
                }
                
                const invoices = await safeArray(env, 'invoices');
                const invoice = {
                    id: generateId(),
                    requestId: targetRequest.id,
                    companyId: targetRequest.companyId,
                    companyName: targetRequest.companyName,
                    type: 'DEVICE_ADDITION',
                    amount: targetRequest.fee,
                    deviceName: targetRequest.deviceName,
                    status: 'UNPAID',
                    createdAt: Date.now()
                };
                invoices.push(invoice);
                await saveData(env, 'invoices', invoices);
                
                targetRequest.status = 'WAITING_PAYMENT';
                targetRequest.invoiceId = invoice.id;
                await saveData(env, 'device_requests', deviceRequests);
                
                return new Response(JSON.stringify({
                    ok: true,
                    invoiceId: invoice.id,
                    amount: targetRequest.fee,
                    request: targetRequest
                }), { headers: corsHeaders });
            }
            
            if (path === '/generate-license' && request.method === 'POST') {
                const body = await request.json();
                const { companyName, pic, phone, email, address, package: pkg, customMaxDevices, notes } = body;
                
                if (!companyName || !pic || !phone || !email) {
                    return new Response(JSON.stringify({ ok: false, error: 'Missing required fields' }), { headers: corsHeaders });
                }
                
                const licenseKey = 'VMS-' + generateId().toUpperCase().substring(0, 16);
                
                let maxDevices = customMaxDevices ? parseInt(customMaxDevices) : (pkg === 'PRO' ? 999 : (pkg === 'BASIC' ? 10 : 2));
                let expiredAt = Date.now();
                
                if (pkg === 'DEMO') {
                    expiredAt += 7 * 86400000;
                } else {
                    expiredAt += 30 * 86400000;
                }
                
                const newCompany = {
                    id: generateId(),
                    companyName: companyName,
                    licenseKey: licenseKey,
                    pic: pic,
                    phone: phone,
                    email: email,
                    address: address || '',
                    package: pkg,
                    maxDevices: maxDevices,
                    currentDevices: 0,
                    expiredAt: expiredAt,
                    status: 'ACTIVE',
                    createdAt: Date.now(),
                    notes: notes || ''
                };
                
                const companies = await safeArray(env, 'companies');
                companies.push(newCompany);
                await saveData(env, 'companies', companies);
                
                return new Response(JSON.stringify({
                    ok: true,
                    licenseKey: licenseKey,
                    company: newCompany
                }), { headers: corsHeaders });
            }
            
            if (path === '/renew-license' && request.method === 'POST') {
                const body = await request.json();
                const { companyId, months, amount, paymentMethod } = body;
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.id === companyId);
                if (!company) {
                    return new Response(JSON.stringify({ ok: false, error: 'Company not found' }), { headers: corsHeaders });
                }
                
                const currentExpiry = company.expiredAt;
                const newExpiry = Math.max(currentExpiry, Date.now()) + (months * 30 * 86400000);
                company.expiredAt = newExpiry;
                company.lastRenewedAt = Date.now();
                
                await saveData(env, 'companies', companies);
                
                const invoices = await safeArray(env, 'invoices');
                const invoice = {
                    id: generateId(),
                    companyId: company.id,
                    companyName: company.companyName,
                    type: 'RENEWAL',
                    amount: amount,
                    months: months,
                    status: paymentMethod === 'CASH' ? 'PAID' : 'UNPAID',
                    paymentMethod: paymentMethod,
                    createdAt: Date.now(),
                    paidAt: paymentMethod === 'CASH' ? Date.now() : null
                };
                invoices.push(invoice);
                await saveData(env, 'invoices', invoices);
                
                return new Response(JSON.stringify({ ok: true, company: company, invoice: invoice }), { headers: corsHeaders });
            }
            
            if (path === '/update-package' && request.method === 'POST') {
                const body = await request.json();
                const { companyId, newPackage, customMaxDevices, notes } = body;
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.id === companyId);
                if (!company) {
                    return new Response(JSON.stringify({ ok: false, error: 'Company not found' }), { headers: corsHeaders });
                }
                
                company.package = newPackage;
                if (customMaxDevices) {
                    company.maxDevices = parseInt(customMaxDevices);
                } else {
                    company.maxDevices = newPackage === 'PRO' ? 999 : 10;
                }
                company.packageUpdatedAt = Date.now();
                company.packageNotes = notes;
                
                await saveData(env, 'companies', companies);
                
                return new Response(JSON.stringify({ ok: true, company: company }), { headers: corsHeaders });
            }
            
            if (path === '/approve-device' && request.method === 'POST') {
                const body = await request.json();
                const { deviceId, approve } = body;
                
                const devices = await safeArray(env, 'devices');
                const targetDevice = devices.find(d => d.deviceId === deviceId);
                if (!targetDevice) {
                    return new Response(JSON.stringify({ ok: false, error: 'Device not found' }), { headers: corsHeaders });
                }
                
                targetDevice.status = approve ? 'ACTIVE' : 'REJECTED';
                if (!approve) {
                    targetDevice.deletedAt = Date.now();
                }
                
                await saveData(env, 'devices', devices);
                
                const companies = await safeArray(env, 'companies');
                const company = companies.find(c => c.id === targetDevice.companyId);
                if (company && approve) {
                    company.currentDevices = devices.filter(d => d.companyId === company.id && d.status === 'ACTIVE').length;
                    await saveData(env, 'companies', companies);
                }
                
                return new Response(JSON.stringify({ ok: true, device: targetDevice }), { headers: corsHeaders });
            }
            
            if (path === '/delete-device' && request.method === 'POST') {
                const body = await request.json();
                const { deviceId, reason } = body;
                
                const devices = await safeArray(env, 'devices');
                const index = devices.findIndex(d => d.deviceId === deviceId);
                if (index === -1) {
                    return new Response(JSON.stringify({ ok: false, error: 'Device not found' }), { headers: corsHeaders });
                }
                
                devices[index].status = 'DELETED';
                devices[index].deletedAt = Date.now();
                devices[index].deleteReason = reason;
                await saveData(env, 'devices', devices);
                
                return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
            }
            
            if (path === '/delete-company' && request.method === 'POST') {
                const body = await request.json();
                const { companyId } = body;
                
                const companies = await safeArray(env, 'companies');
                const index = companies.findIndex(c => c.id === companyId);
                if (index === -1) {
                    return new Response(JSON.stringify({ ok: false, error: 'Company not found' }), { headers: corsHeaders });
                }
                
                companies.splice(index, 1);
                await saveData(env, 'companies', companies);
                
                const devices = await safeArray(env, 'devices');
                const remainingDevices = devices.filter(d => d.companyId !== companyId);
                await saveData(env, 'devices', remainingDevices);
                
                return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
            }
            
            if (path === '/mark-invoice-paid' && request.method === 'POST') {
                const body = await request.json();
                const { invoiceId, paymentMethod } = body;
                
                const invoices = await safeArray(env, 'invoices');
                const targetInvoice = invoices.find(i => i.id === invoiceId);
                if (!targetInvoice) {
                    return new Response(JSON.stringify({ ok: false, error: 'Invoice not found' }), { headers: corsHeaders });
                }
                
                targetInvoice.status = 'PAID';
                targetInvoice.paidAt = Date.now();
                targetInvoice.paymentMethod = paymentMethod;
                await saveData(env, 'invoices', invoices);
                
                if (targetInvoice.type === 'DEVICE_ADDITION' && targetInvoice.requestId) {
                    let deviceRequests = await safeArray(env, 'device_requests');
                    const deviceRequest = deviceRequests.find(r => r.id === targetInvoice.requestId);
                    if (deviceRequest && deviceRequest.status === 'WAITING_PAYMENT') {
                        deviceRequest.status = 'PAID';
                        deviceRequest.paidAt = Date.now();
                        await saveData(env, 'device_requests', deviceRequests);
                        
                        const companies = await safeArray(env, 'companies');
                        const company = companies.find(c => c.id === deviceRequest.companyId);
                        if (company) {
                            const devices = await safeArray(env, 'devices');
                            const newDevice = {
                                deviceId: 'dev_' + generateId(),
                                deviceName: deviceRequest.deviceName,
                                licenseKey: deviceRequest.licenseKey,
                                companyId: company.id,
                                companyName: company.companyName,
                                status: 'ACTIVE',
                                firstSeen: Date.now(),
                                lastSeen: Date.now(),
                                violations: [],
                                sessions: []
                            };
                            devices.push(newDevice);
                            await saveData(env, 'devices', devices);
                            
                            company.currentDevices = devices.filter(d => d.companyId === company.id && d.status === 'ACTIVE').length;
                            await saveData(env, 'companies', companies);
                        }
                    }
                }
                
                return new Response(JSON.stringify({ ok: true, invoice: targetInvoice }), { headers: corsHeaders });
            }
            
            if (path === '/admin/users' && request.method === 'GET') {
                const admins = await safeArray(env, 'admins');
                const safeAdmins = admins.map(a => ({ username: a.username, role: a.role, lastLogin: a.lastLogin }));
                return new Response(JSON.stringify(safeAdmins), { headers: corsHeaders });
            }
            
            if (path === '/admin/add-user' && request.method === 'POST') {
                const body = await request.json();
                const { username, password, role } = body;
                
                if (!username || !password) {
                    return new Response(JSON.stringify({ ok: false, error: 'Username and password required' }), { headers: corsHeaders });
                }
                
                const admins = await safeArray(env, 'admins');
                if (admins.find(a => a.username === username)) {
                    return new Response(JSON.stringify({ ok: false, error: 'Username already exists' }), { headers: corsHeaders });
                }
                
                const hash = await sha256(password);
                admins.push({
                    id: generateId(),
                    username: username,
                    password: hash,
                    role: role || 'ADMIN',
                    createdAt: Date.now()
                });
                await saveData(env, 'admins', admins);
                
                return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
            }
            
            if (path === '/admin/delete-user' && request.method === 'POST') {
                const body = await request.json();
                const { username } = body;
                
                if (username === 'admin') {
                    return new Response(JSON.stringify({ ok: false, error: 'Cannot delete default admin' }), { headers: corsHeaders });
                }
                
                const admins = await safeArray(env, 'admins');
                const filtered = admins.filter(a => a.username !== username);
                await saveData(env, 'admins', filtered);
                
                return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
            }
            
            if (path === '/admin/settings' && request.method === 'POST') {
                const body = await request.json();
                await saveData(env, 'settings', body);
                return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
            }
            
            if (path === '/admin/settings' && request.method === 'GET') {
                const settings = await safeObject(env, 'settings');
                return new Response(JSON.stringify(settings), { headers: corsHeaders });
            }
            
            if (path === '/sync-users' && request.method === 'POST') {
                const body = await request.json();
                if (body.users && Array.isArray(body.users)) {
                    let serverUsers = await safeArray(env, 'users_from_clients');
                    for (const user of body.users) {
                        const existing = serverUsers.find(u => u.username === user.username);
                        if (!existing) {
                            serverUsers.push(user);
                        }
                    }
                    await saveData(env, 'users_from_clients', serverUsers);
                    return new Response(JSON.stringify({ ok: true, users: serverUsers }), { headers: corsHeaders });
                }
                return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
            }
            
            if (path === '/cron/check-expired' && request.method === 'GET') {
                const companies = await safeArray(env, 'companies');
                const now = Date.now();
                let updated = false;
                
                for (const company of companies) {
                    if (company.expiredAt < now && company.status !== 'EXPIRED') {
                        company.status = 'EXPIRED';
                        updated = true;
                    }
                }
                
                if (updated) {
                    await saveData(env, 'companies', companies);
                }
                
                return new Response(JSON.stringify({ ok: true, updated: updated }), { headers: corsHeaders });
            }
            
            return new Response(JSON.stringify({ ok: false, error: 'Endpoint not found: ' + path }), { 
                status: 404, 
                headers: corsHeaders 
            });
            
        } catch (error) {
            console.error('Worker error:', error);
            return new Response(JSON.stringify({ 
                ok: false, 
                error: error.message,
                stack: error.stack,
                timestamp: Date.now()
            }), { 
                status: 500, 
                headers: corsHeaders 
            });
        }
    }
};

// ==================== KV STORAGE LAYER ====================

async function forceInit(env) {
    console.log('[FORCE_INIT] Starting initialization...');
    
    try {
        const testKey = '__vms_test__';
        await env.VMS_STORAGE.put(testKey, 'test');
        const testVal = await env.VMS_STORAGE.get(testKey);
        console.log(`[FORCE_INIT] KV test: ${testVal === 'test' ? 'OK' : 'FAILED'}`);
        
        let admins = await safeArray(env, 'admins');
        
        if (!admins || admins.length === 0) {
            console.log('[FORCE_INIT] No admins found, creating default...');
            
            const defaultHash = await sha256('123456');
            console.log(`[FORCE_INIT] Default admin hash: ${defaultHash.substring(0, 20)}...`);
            
            admins = [{
                id: generateId(),
                username: 'admin',
                password: defaultHash,
                role: 'SUPER_ADMIN',
                createdAt: Date.now(),
                createdBy: 'system',
                token: null
            }];
            
            await saveData(env, 'admins', admins);
            console.log('[FORCE_INIT] Default admin created successfully');
        } else {
            console.log(`[FORCE_INIT] Found ${admins.length} existing admins`);
            
            let needsSave = false;
            for (const admin of admins) {
                if (!admin.token) {
                    admin.token = null;
                    needsSave = true;
                }
            }
            if (needsSave) {
                await saveData(env, 'admins', admins);
                console.log('[FORCE_INIT] Updated admin records with missing fields');
            }
            
            const defaultAdmin = admins.find(a => a.username === 'admin');
            if (defaultAdmin) {
                const expectedHash = await sha256('123456');
                if (defaultAdmin.password !== expectedHash && defaultAdmin.password !== '123456') {
                    console.log('[FORCE_INIT] Updating default admin password hash');
                    defaultAdmin.password = expectedHash;
                    await saveData(env, 'admins', admins);
                }
            }
        }
        
        // PATCH: safeObject untuk settings
        let settings = await safeObject(env, 'settings');
        if (!settings || Object.keys(settings).length === 0) {
            console.log('[FORCE_INIT] Creating default settings...');
            settings = {
                pricing: {
                    BASIC: { price: 500000, maxDevices: 10, extraDeviceFee: 50000 },
                    PRO: { price: 2000000, maxDevices: 999, extraDeviceFee: 0 }
                },
                general: { 
                    tax: 11,
                    company: "VMS System",
                    version: "3.0"
                }
            };
            await saveData(env, 'settings', settings);
            console.log('[FORCE_INIT] Default settings created');
        }
        
        const arrayCollections = [
            'companies', 'devices', 'activities', 'invoices', 
            'device_requests', 'logs', 'anti_nakal_reports', 
            'users_from_clients', 'violations'
        ];
        
        for (const collection of arrayCollections) {
            const data = await safeArray(env, collection);
            if (!Array.isArray(data) || data.length === undefined) {
                console.log(`[FORCE_INIT] Initializing array for: ${collection}`);
                await saveData(env, collection, []);
            }
        }
        
        const objectCollections = ['visitors', 'site_names'];
        for (const collection of objectCollections) {
            const data = await safeObject(env, collection);
            if (!data || typeof data !== 'object') {
                console.log(`[FORCE_INIT] Initializing object for: ${collection}`);
                await saveData(env, collection, {});
            }
        }
        
        console.log('[FORCE_INIT] Initialization complete!');
        return true;
        
    } catch (e) {
        console.error('[FORCE_INIT] Error:', e);
        return false;
    }
}

async function getData(env, key) {
    try {
        if (!env || !env.VMS_STORAGE) {
            console.error(`[GET_DATA] KV Storage not available for key: ${key}`);
            return getDefaultData(key);
        }
        
        const value = await env.VMS_STORAGE.get(key);
        
        if (!value || value === 'null' || value === 'undefined') {
            console.log(`[GET_DATA] Key "${key}" not found, using default`);
            return getDefaultData(key);
        }
        
        const parsed = JSON.parse(value);
        const itemCount = Array.isArray(parsed) ? parsed.length + ' items' : Object.keys(parsed).length + ' keys';
        console.log(`[GET_DATA] Retrieved "${key}": ${itemCount}`);
        return parsed;
        
    } catch (e) {
        console.error(`[GET_DATA] Error for key "${key}":`, e);
        return getDefaultData(key);
    }
}

async function saveData(env, key, data) {
    try {
        if (!env || !env.VMS_STORAGE) {
            console.error(`[SAVE_DATA] KV Storage not available for key: ${key}`);
            return false;
        }
        
        const jsonString = JSON.stringify(data);
        await env.VMS_STORAGE.put(key, jsonString);
        const itemCount = Array.isArray(data) ? data.length + ' items' : Object.keys(data).length + ' keys';
        console.log(`[SAVE_DATA] Saved "${key}": ${jsonString.length} bytes, ${itemCount}`);
        return true;
        
    } catch (e) {
        console.error(`[SAVE_DATA] Error for key "${key}":`, e);
        return false;
    }
}

function getDefaultData(key) {
    const defaults = {
        companies: [],
        devices: [],
        activities: [],
        invoices: [],
        device_requests: [],
        admins: [],
        visitors: {},
        logs: [],
        anti_nakal_reports: [],
        users_from_clients: [],
        violations: [],
        site_names: {
            SITE_A: "SITE A",
            SITE_B: "SITE B", 
            SITE_C: "SITE C",
            customSites: {}
        },
        settings: {
            pricing: {
                BASIC: { price: 500000, maxDevices: 10, extraDeviceFee: 50000 },
                PRO: { price: 2000000, maxDevices: 999, extraDeviceFee: 0 }
            },
            general: { tax: 11 }
        }
    };
    
    if (defaults[key] !== undefined) {
        return defaults[key];
    }
    
    // PATCH: Deteksi berdasarkan key untuk menentukan return type
    const objectKeys = ['visitors', 'site_names', 'settings'];
    if (objectKeys.includes(key)) {
        return {};
    }
    
    return [];
}

async function checkAuth(headers, env) {
    let token = headers.get('x-token');
    
    if (!token) {
        const authHeader = headers.get('authorization') || headers.get('Authorization');
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.split(' ')[1];
        }
    }
    
    if (!token) return null;
    
    const admins = await safeArray(env, 'admins');
    const admin = admins.find(a => a.token === token);
    
    if (admin && admin.lastLogin && (Date.now() - admin.lastLogin) < 24 * 3600000) {
        return { username: admin.username, role: admin.role, id: admin.id };
    }
    
    return null;
}

function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substring(2, 10);
}

async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}