export namespace config {
	
	export class ClientConfig {
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
	
	    static createFrom(source: any = {}) {
	        return new ClientConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
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
	    }
	}

}

