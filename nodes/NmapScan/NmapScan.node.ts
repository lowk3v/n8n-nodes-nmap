import {
    IDataObject, IExecuteFunctions, INodeExecutionData,
    INodeType,
    INodeTypeDescription, NodeConnectionType,
    NodeOperationError,
} from 'n8n-workflow';
import {ShellUtils} from "./utils/ShellUtils";
import {NmapUtils} from "./utils/NmapUtils";

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
            }
        ],
        properties: [
            {
                displayName: 'Operation',
                name: 'operation',
                type: 'options',
                noDataExpression: true,
                options: [
                    {
                        name: 'Discovery network',
                        value: 'discovery_network',
                        description: 'Discovery network',
                        action: 'Discovery network',
                    },
                    {
                        name: 'Port scan on a host',
                        value: 'port_scan',
                        description: 'Port scan on a host',
                        action: 'Port scan on a host',
                    },
                ],
                default: 'discovery_network',
            },
            {
                displayName: 'Target Network Range',
                name: 'network_range',
                type: 'string',
                displayOptions: {
                    show: {
                        operation: ['discovery_network', 'quick_scan'],
                    },
                },
                required: true,
                default: '192.168.0.0/24',
                description: 'The LAN IP Range to target',
            },
            {
                displayName: 'Target Host',
                name: 'host',
                type: 'string',
                displayOptions: {
                    show: {
                        operation: ['port_scan'],
                    },
                },
                required: true,
                default: '192.168.0.1',
                description: 'The Host or Url to target',
            },
            {
                displayName: 'Options',
                name: 'options',
                type: 'collection',
                placeholder: 'Add option',
                displayOptions: {
                    show: {
                        operation: ['port_scan'],
                    },
                },
                default: {},
                options: [
                    {
                        displayName: 'Put Ports in Field',
                        name: 'ports_values',
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

            item = {...items[itemIndex]};
            const newItem: INodeExecutionData = {
                json: item.json,
                pairedItem: {
                    item: itemIndex,
                },
            };

            // Parameters & Options
            const operation = this.getNodeParameter('operation', itemIndex) as string;

            const options = this.getNodeParameter('options', itemIndex) as IDataObject;

            // Credentials
            const credentials = await this.getCredentials('onlyPassword');


            let command: string = `nmap -help`;

            if (operation === 'discovery_network') {
                const network_range = this.getNodeParameter('network_range', itemIndex) as string;
                command = `nmap -sn ${network_range}`;
            } else if (operation === 'port_scan') {
                const host = this.getNodeParameter('host', itemIndex) as string;
                command = `nmap -T4 -F ${host}`;
            }

            console.log(`Nmap Scan starting ${command}`);

            const nmapUtils = new NmapUtils();
            const shellUtils = new ShellUtils();
            await shellUtils.sudoCommand(command, credentials.password).then(output => {
                console.log(`Nmap Scan done ${command}`);

                if (operation === 'discovery_network') {

                    nmapUtils.parseNmapDiscovery(output).forEach(value => {
                        returnItems.push({
                            json: value
                        });
                    });


                } else if (operation === 'port_scan') {

                    newItem.json![options.ports_values as string || 'ports'] = nmapUtils.parseNmapPorts(output);
                    returnItems.push(newItem);

                }


            }).catch(e => {
                throw new NodeOperationError(this.getNode(), e);
            });
        }

        return [returnItems];
    }
}
