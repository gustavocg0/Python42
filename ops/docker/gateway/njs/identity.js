/**
 * Client-cert -> identity-header mapping for the agent mTLS listener
 * (ADR-0006, SEC-14). dataplane-api issues device certs with:
 *   subject  CN=<device_id>
 *   URI SAN  urn:platform:tenant:<tenant_uuid>:device:<device_id>
 * (services/dataplane/src/dataplane/core/ca.py — san_uri() is BINDING).
 *
 * Stock nginx has no SAN variable, so we locate the URN inside the DER
 * bytes of $ssl_client_raw_cert. The URN is plain ASCII inside the
 * SubjectAltName extension, and its charset ([a-z0-9:_-]) cannot occur
 * ambiguously, so a substring match is deterministic for certs WE issued.
 * Dev/POC-grade: a full ASN.1 parse (or SAN support at the LB) belongs in
 * the production stamp.
 *
 * These values are only forwarded on locations that already require
 * $ssl_client_verify == SUCCESS (see soc.conf.template), i.e. the cert
 * chains to the dev CA. Unverified/absent cert => empty strings.
 */

function _sanMatch(r) {
    var pem = r.variables.ssl_client_raw_cert;
    if (!pem) {
        return null;
    }
    try {
        var b64 = pem
            .replace(/-----[A-Z ]+-----/g, '')
            .replace(/[^A-Za-z0-9+/=]/g, '');
        var der = Buffer.from(b64, 'base64').toString('latin1');
        return der.match(
            /urn:platform:tenant:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):device:([A-Za-z0-9_.-]+)/
        );
    } catch (e) {
        return null;
    }
}

function deviceId(r) {
    var m = _sanMatch(r);
    return m ? m[2] : '';
}

function deviceTenant(r) {
    var m = _sanMatch(r);
    return m ? m[1] : '';
}

/**
 * Canonical serial: dataplane stores `format(serial, "x")` (lowercase hex,
 * no leading zeros); nginx $ssl_client_serial is uppercase and may carry a
 * leading zero pad. Normalize so the SEC-10 allowlist compare matches.
 */
function deviceSerial(r) {
    var s = r.variables.ssl_client_serial || '';
    return s.toLowerCase().replace(/^0+/, '');
}

export default { deviceId, deviceTenant, deviceSerial };
