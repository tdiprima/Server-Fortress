This script turns Lynis wall-of-text into clean prioritized summary: 
 
1. Big score up top — color-coded: green (80+), yellow (60-79), red (below 60), with grade label
2. Warnings first — grouped by category (SSH, Kernel, Firewall, etc). These need fixing
3. Suggestions second — same grouping. Improve when ready
4. Noise stripped — no test details, no debug info, no raw data
 
## Usage:

```sh
sudo ./lynis-report.sh                # fresh scan + terminal summary
sudo ./lynis-report.sh --report-only  # parse last scan (no re-run)
sudo ./lynis-report.sh --html         # also save HTML file
sudo ./lynis-report.sh --report-only --html
```

## Terminal output looks like:

    Hardening Score:  67 / 100  (FAIR)                                                                       
                                                                                                           
    WARNINGS (3) — Fix these first                                                                           
                                  
    [Kernel]                                                                                                 
      ! KRNL-5830    Reboot of system is most likely needed                                                
                                                           
    [SSH]                                                                                                    
      ! SSH-7408     Weak SSH configuration found
                                                                                                             
    SUGGESTIONS (12) — Improve when ready                                                                    
                                         
    [Authentication]                                                                                         
      - AUTH-9286    Configure password hashing rounds                                                     
      - AUTH-9328    Default umask in /etc/profile could be more strict
                                                                                                             
    [Boot & GRUB]                                                                                            
      - BOOT-5122    Set a password on GRUB boot loader
 
Categories auto-detected from test IDs. HTML version has same structure, styled, good for sharing or 
archiving alongside your baseline snapshots.

<br>
