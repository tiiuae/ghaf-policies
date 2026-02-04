function FindProxyForURL(url, host) {
    // Proxy and no-proxy settings
    var proxy = "PROXY 192.168.100.1:3128";
    var noProxy = [
        "192.168.101.10",  // Admin VM
        "192.168.100.10",  // Admin VM
        "127.0.0.1",
        "localhost"
    ];

    // VPN-only addresses that should bypass the proxy
    // Jira can be access without VPN, so it's removed
    var vpnOnlyAddresses = [
        "vpn.tii.ae",
        "access.tii.ae",
        "confluence.tii.ae",
        "i-service.tii.ae",
        "catalyst.atrc.ae",
        "151.253.154.18"
    ];

    // Check if the host matches any of the noProxy addresses
    for (var i = 0; i < noProxy.length; i++) {
        if (shExpMatch(host, noProxy[i])) {
            return "DIRECT";
        }
    }

    // Check if the host matches any of the VPN-only addresses
    for (var j = 0; j < vpnOnlyAddresses.length; j++) {
        if (shExpMatch(host, vpnOnlyAddresses[j])) {
            return "DIRECT";
        }
    }

    // Default: use proxy
    return proxy;
}
