import {IDataObject} from "n8n-workflow";

export class NmapUtils {

    parseNmapDiscovery(output: string): IDataObject[] {
        let results: IDataObject[] = [];

        const lines: string[] = output
            .split('\n')
            .filter((line) => line.trim() !== ''); // Split lines and filter out empty lines

        for (let i = 0; i < lines.length; i++) {
            let newDevice: IDataObject = {};

            const regex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
            const match = lines[i].match(regex);
            if (match !== null) {
                newDevice["ip"] = match[0].trim();

                for (let y = i; y < lines.length; y++) {
                    if (lines[y].includes("MAC Address:")) {
                        const macRegex = /([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})/;
                        const macMatch = lines[y].match(macRegex);
                        if (macMatch !== null) {
                            newDevice["mac"] = macMatch[0].trim();
                        }

                        const nameRegex = /\((.*?)\)/;
                        const nameMatch = lines[y].match(nameRegex);
                        if (nameMatch !== null) {
                            newDevice["name"] = nameMatch[1].trim();
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

    parseNmapPorts(output: string): IDataObject[] {
        let results: IDataObject[] = [];

        const regex = /(\d+\/\w+)\s+(\w+)\s+(.+)/g;

        let match;
        while ((match = regex.exec(output)) !== null) {
            let newPort: IDataObject = {};

            newPort["port"] = match[1].trim();
            newPort["state"] = match[2].trim();
            newPort["service"] = match[3].trim();

            results.push(newPort);
        }

        return results;
    }

}