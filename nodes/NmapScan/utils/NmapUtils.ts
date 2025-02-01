import { IDataObject } from 'n8n-workflow';

export class NmapUtils {
	parseNmapQuickScan(output: string): IDataObject[] {
		let results: IDataObject[] = [];

		const lines: string[] = output.split('\n').filter((line) => line.trim() !== ''); // Split lines and filter out empty lines

		for (let i = 0; i < lines.length; i++) {
			let newDevice: IDataObject = {};

			const regex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
			const match = lines[i].match(regex);
			if (match !== null) {
				newDevice['ip'] = match[0].trim();

				for (let y = i; y < lines.length; y++) {
					if (lines[y].includes('MAC Address:')) {
						const macRegex = /([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})/;
						const macMatch = lines[y].match(macRegex);
						if (macMatch !== null) {
							newDevice['mac'] = macMatch[0].trim();
						}

						const nameRegex = /\((.*?)\)/;
						const nameMatch = lines[y].match(nameRegex);
						if (nameMatch !== null) {
							newDevice['name'] = nameMatch[1].trim();
						}

						results.push(newDevice);

						i = y--;

						break;
					}
				}
			}
		}
		return results;
	}

	/*
    Nmap scan report for 192.168.0.254
    Host is up (0.019s latency).
    Not shown: 987 closed tcp ports (reset)
    PORT     STATE SERVICE
    21/tcp   open  ftp
    53/tcp   open  domain
    80/tcp   open  http
    443/tcp  open  https
    445/tcp  open  microsoft-ds
    548/tcp  open  afp
    554/tcp  open  rtsp
    2020/tcp open  xinupageserver
    5000/tcp open  upnp
    5357/tcp open  wsdapi
    5678/tcp open  rrac
    8090/tcp open  opsmessaging
    9091/tcp open  xmltec-xmlmail
    MAC Address: 00:24:D4:A6:30:69 (Freebox SAS)
    */
	parseNmapDiscovery(output: string, ports_field: string): IDataObject[] {
		let results: IDataObject[] = [];

		const lines: string[] = output.split('\n').filter((line) => line.trim() !== ''); // Split lines and filter out empty lines

		for (let i = 0; i < lines.length; i++) {
			let newDevice: IDataObject = {};

			const regex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
			const match = lines[i].match(regex);
			if (match !== null) {
				// New device
				newDevice['ip'] = match[0].trim();

				// List ports
				while (!lines[i].includes('PORT')) {
					i++;
				}

				const portRegex = /(\d+\/\w+)\s+(\w+)\s+(.+)/;
				const portResult: IDataObject[] = [];
				for (let y = i + 1; y < lines.length; y++) {
					const portMatch = lines[y].match(portRegex);
					if (portMatch !== null) {
						let newPort: IDataObject = {};

						newPort['port'] = portMatch[1].trim();
						newPort['state'] = portMatch[2].trim();
						newPort['service'] = portMatch[3].trim();

						portResult.push(newPort);
					} else {
						newDevice[ports_field] = portResult;
						i = y - 1;
						break;
					}
				}

				// List mac & name
				for (let y = i; y < lines.length; y++) {
					if (lines[y].includes('MAC Address:')) {
						const macRegex = /([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})/;
						const macMatch = lines[y].match(macRegex);
						if (macMatch !== null) {
							newDevice['mac'] = macMatch[0].trim();
						}

						const nameRegex = /\((.*?)\)/;
						const nameMatch = lines[y].match(nameRegex);
						if (nameMatch !== null) {
							newDevice['name'] = nameMatch[1].trim();
						}

						results.push(newDevice);

						i = y - 1;
						break;
					}
				}
			}
		}
		return results;
	}

	parseNmapPorts(output: string): IDataObject[] {
		let results: IDataObject[] = [];

		const regex = /(\d+\/\w+)\s+(\w+)\s+(.+)/g;

		let match;
		while ((match = regex.exec(output)) !== null) {
			let newPort: IDataObject = {};

			newPort['port'] = match[1].trim();
			newPort['state'] = match[2].trim();
			newPort['service'] = match[3].trim();

			results.push(newPort);
		}
		return results;
	}
}
