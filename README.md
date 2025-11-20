cat > README.md << 'EOF'
# VRecon - Automated Recon Pipeline

VRecon is a Bash-based recon orchestrator for authorized bug bounty /
security testing. It chains tools like subfinder, amass, naabu, httpx,
nuclei, katana, and gau to perform subdomain enumeration, port scanning,
HTTP probing, and endpoint discovery.

## Usage

```bash
chmod +x VRecon.sh
./VRecon.sh example.com
