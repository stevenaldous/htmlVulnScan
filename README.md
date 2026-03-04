# htmlVulnScan
This is bash script with instructions on simplifying vulnerability scanning for performing vulnerability assessments and penetration testing. This should only be used on systems you legally have access to and is intended to be used in an educational capacity.

OS Requirements:
This script is built for a Kali Linux environment. 

Getting Started:
This repo contains two files.
- installer.sh
- nmap_vuln_scan.sh

To simplfy setup, the installer.sh will create the folders within the directory for the vulneerabilty script and the reports. It will also modify permissions allowing for all machine users to access and view the reports. To chane those permissions, simply modify the chmod on line 30 and line 47.

# 1. Run the installer (once)
sudo bash install.sh

# 2. Run scans from anywhere
sudo /scripts/nmap_vuln_scan.sh 192.168.1.0/24









 

Notes and Attribution:
While the code was tested on modified by the repository owner, Anthropics Claude.ai was used to create this tool. 
