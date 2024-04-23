
# Starware

Starware is a comprehensive installer script that integrates two powerful tools into a single seamless installation process on your system: [r77-rootkit](https://github.com/bytecode77/r77-rootkit) and [Quasar RAT](https://github.com/quasar/Quasar). This tool is designed for advanced users looking to monitor and manage remote systems effectively.

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


## Usage

After installation, Starware can be configured via the generated configuration files or using the upcoming Starware Tools.

## Caution

This software is intended for educational and legally sanctioned purposes only. Users are responsible for ensuring they comply with all applicable laws and regulations.

## License

This project is licensed under [license name] - see the [LICENSE.md](LICENSE.md) file for details.

## Acknowledgments

- Thanks to [bytecode77](https://github.com/bytecode77) for the r77-rootkit.
- Thanks to the developers of [Quasar](https://github.com/quasar/Quasar).
