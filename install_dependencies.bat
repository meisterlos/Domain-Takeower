@echo off
echo Installing Domain Takeover Scanner Dependencies...
echo.

echo Installing Python packages...
pip install -r requirements.txt

echo.
echo Installing Subfinder (optional but recommended)...
echo Please download Subfinder from: https://github.com/projectdiscovery/subfinder
echo And add it to your PATH for enhanced subdomain discovery

echo.
echo Installation completed!
echo You can now run: python domain_takeover_scanner.py
pause
