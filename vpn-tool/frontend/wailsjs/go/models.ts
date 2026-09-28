export namespace config {
	
	export class ClientConfig {
	    name: string;
	    ip: string;
	    port: number;
	    portVPN: number;
	    username: string;
	    password: string;
	    useDHCP: boolean;
	    staticIP: string;
	    staticMask: string;
	    skipCertVerify: boolean;
	    obfsEnabled: boolean;
	    obfsPassword: string;
	    p2pDisabled: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ClientConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.ip = source["ip"];
	        this.port = source["port"];
	        this.portVPN = source["portVPN"];
	        this.username = source["username"];
	        this.password = source["password"];
	        this.useDHCP = source["useDHCP"];
	        this.staticIP = source["staticIP"];
	        this.staticMask = source["staticMask"];
	        this.skipCertVerify = source["skipCertVerify"];
	        this.obfsEnabled = source["obfsEnabled"];
	        this.obfsPassword = source["obfsPassword"];
	        this.p2pDisabled = source["p2pDisabled"];
	    }
	}

}

export namespace quic {
	
	export class PathInfo {
	    peerVip: string;
	    state: string;
	    role: string;
	    rttDirectMs: number;
	    bytesUp: number;
	    bytesDown: number;
	    directSince: number;
	    warn?: string;
	
	    static createFrom(source: any = {}) {
	        return new PathInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.peerVip = source["peerVip"];
	        this.state = source["state"];
	        this.role = source["role"];
	        this.rttDirectMs = source["rttDirectMs"];
	        this.bytesUp = source["bytesUp"];
	        this.bytesDown = source["bytesDown"];
	        this.directSince = source["directSince"];
	        this.warn = source["warn"];
	    }
	}
	export class SignalPeer {
	    vip: string;
	    online: boolean;
	    publicAddr: string;
	    natType: string;
	    metadata: string;
	    signalReady: boolean;
	    relayRttMs: number;
	
	    static createFrom(source: any = {}) {
	        return new SignalPeer(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.vip = source["vip"];
	        this.online = source["online"];
	        this.publicAddr = source["publicAddr"];
	        this.natType = source["natType"];
	        this.metadata = source["metadata"];
	        this.signalReady = source["signalReady"];
	        this.relayRttMs = source["relayRttMs"];
	    }
	}

}

