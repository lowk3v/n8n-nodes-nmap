import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeConnectionType,
	NodeOperationError,
} from 'n8n-workflow';
import { ShellUtils } from './utils/ShellUtils';
import { NmapUtils } from './utils/NmapUtils';

export class NmapScan implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Nmap Scan',
		name: 'nmapScan',
		icon: 'file:NmapLogo.svg',
		group: ['output'],
		version: 1,
		triggerPanel: false,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Scan with nmap command',
		defaults: {
			name: 'Nmap Scan',
		},
		inputs: [NodeConnectionType.Main],
		outputs: [NodeConnectionType.Main],
		credentials: [
			{
				displayName: 'Local Sudo Password',
				name: 'onlyPassword',
				required: true,
				//testedBy: 'localConnectionTest',
			},
		],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Quick Scan Network',
						value: 'quick_scan_network',
						description: 'Scan network with fast ping (-sn)',
						action: 'Quick scan network',
					},
					{
						name: 'Discovery Network',
						value: 'discovery_network',
						description: 'Discovery network with device and ports (-sS)',
						action: 'Discovery network',
					},
					{
						name: 'Ports Fast Scan',
						value: 'ports_fast_scan',
						description: 'Ports fast scan a host (-F)',
						action: 'Ports fast scan',
					},
					{
						name: 'All Ports Scan',
						value: 'all_ports_scan',
						description: 'All Ports scan a host (-p-)',
						action: 'All ports scan',
					},
				],
				default: 'discovery_network',
			},
			{
				displayName: 'Target Network Range / Host / IP',
				name: 'network_range',
				type: 'string',
				required: true,
				default: '192.168.0.0/24',
				description: 'Define the target to scan',
			},
			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add option',
				default: {},
				options: [
					{
						displayName: 'Aggressive Mode',
						name: 'aggressive_mode',
						type: 'number',
						default: 5,
						description: 'For faster execution (-T5)',
					},
					{
						displayName: 'Check Top Ports',
						name: 'top_ports',
						type: 'number',
						default: 1000,
						description: 'Check usually top ports (--top-ports 1000)',
					},
					{
						displayName: 'Host Discovery',
						name: 'host_discovery',
						type: 'boolean',
						default: false,
						description: 'Enable host discovery, faster if disable (-Pn)',
					},
					{
						displayName: 'Put Result in Field',
						name: 'ports_field',
						type: 'string',
						default: 'ports',
						description: 'The name of the output field to put the data in',
					},
				],
			},
		],
	};

	methods = {
		/*
        credentialTest: {
            async localConnectionTest(
                this: ICredentialTestFunctions,
                credential: ICredentialsDecrypted,
            ): Promise<INodeCredentialTestResult> {
                const credentials = credential.data as IDataObject;

                const shellUtils = new ShellUtils();
                const command = "echo 'success'";

                console.log(`LocalPassword checking ${command}`);

                await shellUtils.sudoCommand(command, credentials.localPassword?.toString()).then(output => {
                    console.log(`LocalPassword checked ${command}`);
                }).catch(error => {
                    const message = `LocalPassword check failed: ${error}`;
                    return {
                        status: 'Error',
                        message,
                    };
                });

                return {
                    status: 'OK',
                    message: 'Connection successful!',
                };
            },
        },
        */
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		let item: INodeExecutionData;
		const returnItems: INodeExecutionData[] = [];

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			item = { ...items[itemIndex] };
			const newItem: INodeExecutionData = {
				json: item.json,
				pairedItem: {
					item: itemIndex,
				},
			};

			// Parameters & Options
			const operation = this.getNodeParameter('operation', itemIndex);
			const network_range = this.getNodeParameter('network_range', itemIndex) as string;

			const options = this.getNodeParameter('options', itemIndex);
			const host_discovery = options.host_discovery ? '' : '-Pn';
			const aggressive_mode = options.aggressive_mode ? '-T5' : '';
			const top_ports = options.top_ports ? '--top-ports ' + options.top_ports : '';
			const ports_field = (options.ports_field as string) || 'ports';

			// Credentials
			const credentials = await this.getCredentials('onlyPassword');

			let command: string = `nmap -help`;

			if (operation === 'quick_scan_network') {
				command = `nmap -sn ${aggressive_mode} ${network_range}`;
			} else if (operation === 'discovery_network') {
				command = `nmap -sS ${host_discovery} ${aggressive_mode} ${top_ports} ${network_range}`;
			} else if (operation === 'ports_fast_scan') {
				command = `nmap -F ${host_discovery} ${aggressive_mode} ${top_ports} ${network_range}`;
			} else if (operation === 'all_ports_scan') {
				command = `nmap -p- ${host_discovery} ${aggressive_mode} ${top_ports} ${network_range}`;
			}

			console.log(`Nmap Scan starting ${command}`);

			const nmapUtils = new NmapUtils();
			const shellUtils = new ShellUtils();

			const workingDirectory = await shellUtils.resolveHomeFolder('~/');
			console.log(workingDirectory);

			await shellUtils
				.sudoCommand(command, workingDirectory, credentials.password)
				.then((output) => {
					console.log(`Nmap Scan done ${command}`);

					if (operation === 'quick_scan_network') {
						nmapUtils.parseNmapQuickScan(output).forEach((value) => {
							returnItems.push({
								json: value,
							});
						});
					} else if (operation === 'discovery_network') {
						nmapUtils.parseNmapDiscovery(output, ports_field).forEach((value) => {
							returnItems.push({
								json: value,
							});
						});
					} else if (operation === 'ports_fast_scan' || operation === 'all_ports_scan') {
						newItem.json[ports_field] = nmapUtils.parseNmapPorts(output);
						returnItems.push(newItem);
					}
				})
				.catch((e) => {
					throw new NodeOperationError(this.getNode(), e);
				});
		}

		return [returnItems];
	}
}
