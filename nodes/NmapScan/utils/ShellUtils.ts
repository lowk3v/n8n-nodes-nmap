import {spawn} from "child_process";
import {CredentialInformation} from "n8n-workflow";

export class ShellUtils {

    async sudoCommand(command: string, password: CredentialInformation | undefined): Promise<string> {
        return new Promise((resolve, reject) => {
            let child = spawn('sudo', ['-S', '-k', '-p', 'pwd:', 'sh', '-c', command]);
            let commandOutput: string = "";
            let commandError: string = "";

            child.stdout.on('data', (data: Buffer) => {
                commandOutput += data.toString();
            });

            child.stderr.on('data', (error: Buffer) => {
                if (error.toString() == 'pwd:') {
                    child.stdin.write(password + '\n');
                } else {
                    closeFunction();
                    //reject(error.toString());
                    commandError = error.toString();
                }
            });

            async function closeFunction() {
                child.kill('SIGHUP');
            }

            child.on('exit', (code) => {
                if (code === 0) {
                    resolve(commandOutput);
                } else {
                    reject(commandError);
                }
            });
        });
    }
}