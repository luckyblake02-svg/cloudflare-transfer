# cloudflare-transfer

**cloudflare-transfer** is a PowerShell script designed to automate the migration of DNS zones from DNSimple (via the CSC registrar backend) to Cloudflare. It streamlines the process of transferring DNS records—keeping your domain registered with CSC while migrating DNS management to Cloudflare. The script adapts records for compatibility, handles URL record processing, updates nameservers, and configures Cloudflare Page Rules programmatically.

## Features

- **Automated DNS Transfers:** Move DNS zones from DNSimple (CSC) to Cloudflare using PowerShell automation.
- **Registrar Independence:** Domains remain with your CSC registrar; only DNS management is transferred.
- **Zone File Parsing:** Adapts DNSimple zone file syntax to be accepted by Cloudflare.
- **URL Record Management:** Splits URL records and creates corresponding Cloudflare Page Rules.
- **API Integration:** Interacts with Cloudflare and CSC APIs for seamless domain and DNS updates.
- **Name Server Management:** Updates CSC nameservers to those provided by Cloudflare automatically.

## How It Works

1. **Retrieve Zone Files:** Fetch zone files for listed domains from DNSimple (CSC backend).
2. **Parse & Convert Records:** Adapt DNS record syntax for Cloudflare and segregate URL records.
3. **Add Domains:** Use Cloudflare API to onboard each domain.
4. **Update Nameservers:** Change CSC nameservers to ones specified by Cloudflare.
5. **Page Rule Automation:** Generate Cloudflare Page Rules for all URL records.

## Requirements

- PowerShell 5.1 or later (Windows, Mac, or Linux with PowerShell Core) **DISCLAIMER: Sometimes this will NEED Powershell 7 or later. Trial and error required.**
- API access to both Cloudflare and CSC (DNSimple) accounts
- API credentials for Cloudflare and CSC
- Domain list file as expected by the script

## Installation

1. Clone the repository:
   ```powershell
   git clone https://github.com/luckyblake02-svg/cloudflare-transfer.git
   cd cloudflare-transfer
   ```
2. Review dependencies listed at the top of the script (e.g., PowerShell modules).

## Usage

1. **Prepare your domain list:**  
   Format a file with domains as required by the script.

2. **Set up credentials:**  
   Export CSC and Cloudflare API keys as environment variables or update the script configuration section.

3. **Run the script:**  
   ```powershell
   .\cloudflare-transfer.ps1
   ```

   Workflow:
   - Retrieves DNS records from CSC (DNSimple)
   - Adapts records to Cloudflare format
   - Transfers domains/DNS to Cloudflare
   - Updates nameservers on CSC
   - Sets Cloudflare Page Rules for URL records

## Notes

- **Safety:** Domain registration remains with CSC; DNS hosting switches to Cloudflare.
- **Manual Review:** Always double-check custom or complex DNS records after migration.
- **Troubleshooting:** Ensure API credentials are accurate and permissions are sufficient. Run a test migration with a non-production domain if possible.

## Contributing

Contributions and issues are welcome! Submit pull requests or file issues for suggested improvements or bugs.

## License

Distributed under the GPLv3 License.

## Disclaimer

This project is provided as-is. It may require customization for edge-case DNS records or rare configurations. Use at your own risk and always back up your current DNS settings before migrating.

**For details and options, read comments within the script file and reference script usage instructions.**
