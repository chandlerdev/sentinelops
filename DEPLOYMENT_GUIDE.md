# Deployment guide (Ubuntu server)

STATUS: **prepared, not executed.** Nothing here has been run on the server yet.
This is a shared company server with many live apps. Follow the rules:

- Never stop/restart other apps; never change existing ports or processes.
- Back up any file before changing it; every step below has a rollback.
- Do not run `docker system prune`; do not touch the firewall.
- Get approval (and tell the network-security person) before the Apache change
  and before the first scan.

Target layout (inside the existing vhost folder, next to the other project):

```
/var/www/Vhost/jjlltdnext.desss-portfolio.com/
├── admin/ backend/ frontend/ public/      (existing project, DO NOT TOUCH)
├── sentinelops_admin/                     Next.js, port 3017
└── sentinelops_backend/                   Spring Boot, port 8096
```

Public URLs: `/sentinelops` (UI) and `/sentinelops-api` (API).

## 0. Pre-checks (read-only)

```bash
ss -tln | grep -E ":(3017|8096)\b" || echo "3017 and 8096 are free"
df -h /var/www | tail -1
pm2 list
ls /var/www/Vhost/jjlltdnext.desss-portfolio.com/
```

## 1. Keep the existing project's git clean

The existing project has a `.git` in that folder. Ignore our folders locally (not committed anywhere):

```bash
cd /var/www/Vhost/jjlltdnext.desss-portfolio.com
printf 'sentinelops_admin/\nsentinelops_backend/\n' >> .git/info/exclude
```

Rollback: remove those two lines from `.git/info/exclude`.

## 2. Database (MySQL 8, needs sudo)

Use a strong password of your own instead of `CHANGE_ME`.

```bash
sudo mysql -e "CREATE DATABASE sentinelops CHARACTER SET utf8mb4;
CREATE USER 'sentinelops'@'localhost' IDENTIFIED BY 'CHANGE_ME';
GRANT ALL ON sentinelops.* TO 'sentinelops'@'localhost'; FLUSH PRIVILEGES;"
```

Rollback: `sudo mysql -e "DROP DATABASE sentinelops; DROP USER 'sentinelops'@'localhost';"` (only if it holds nothing you need).

### 2b. Test the migrations on MySQL 8 first (throwaway database)

The Phase 1-5 migrations (`V2` to `V4`) were only run on MariaDB 10.4 so far. Before the real start, prove it on the server's MySQL 8:

```bash
sudo mysql -e "CREATE DATABASE sentinelops_migtest CHARACTER SET utf8mb4; GRANT ALL ON sentinelops_migtest.* TO 'sentinelops'@'localhost';"
# start the backend once against sentinelops_migtest (change the JDBC URL temporarily); expect "Successfully applied 4 migrations"
sudo mysql -e "DROP DATABASE sentinelops_migtest;"
```

If it fails, send me the error; do not edit the database by hand.

## 3. Upload the code

Copy `sentinelops_backend/` and `sentinelops_admin/` from the PC to the folders above
(WinSCP/FileZilla), **excluding** `node_modules`, `.next`, `target`, and the local
`application.properties` / `.env.local`.

## 4. Backend

```bash
cd /var/www/Vhost/jjlltdnext.desss-portfolio.com/sentinelops_backend/src/main/resources
cp application.properties.example application.properties
nano application.properties
#   server.port=8096
#   spring.datasource.username=sentinelops / password=<from step 2>
#   sentinelops.security.jwt-secret=<openssl rand -base64 48>
#   sentinelops.security.cors-allowed-origins=https://jjlltdnext.desss-portfolio.com
#   sentinelops.security.four-eyes=true
#   sentinelops.security.secret-key=<openssl rand -base64 32>   (only needed for authenticated scans; back it up)
#   sentinelops.scan.blocked-addresses=75.148.178.10      <- THIS SERVER'S public IP: nothing on the shared server can ever be scanned
#   sentinelops.scan.lab.enabled=false                     (turn on only in Phase 2, with the Juice Shop network)
#   sentinelops.verification.dns-servers=1.1.1.1,8.8.8.8   (if the server cannot reach them, leave empty to use its own resolver)
cd ../../..
mvn clean package -DskipTests
# First start on the empty DB creates the demo admin (set your own password, 10+ chars):
SEED_ADMIN_PASSWORD='<your-password>' java -jar target/sentinelops-backend-0.2.0.jar --spring.profiles.active=seed
```

Stop it (Ctrl+C) once you see "Started SentinelOpsApplication". Then run it normally.
Process manager: to be decided with you (same as the other apps: PM2 or `java -jar`,
or a dedicated systemd unit). Example with PM2:

```bash
pm2 start "java -jar target/sentinelops-backend-0.2.0.jar" --name sentinelops-backend
pm2 save
```

Check: `curl http://127.0.0.1:8096/api/health` -> `{"status":"UP",...,"database":"UP"}`.
Rollback: `pm2 delete sentinelops-backend`.

## 5. Admin app

```bash
cd /var/www/Vhost/jjlltdnext.desss-portfolio.com/sentinelops_admin
printf 'NEXT_PUBLIC_API_BASE=https://jjlltdnext.desss-portfolio.com/sentinelops-api\n' > .env.production
npm ci
npm run build
pm2 start npm --name sentinelops-admin -- start     # runs "next start -p 3017"
pm2 save
```

Check: `curl -I http://127.0.0.1:3017/sentinelops`.
Rollback: `pm2 delete sentinelops-admin`.

## 6. Apache (ASK FIRST — this changes a live site's config)

File: `/etc/apache2/sites-enabled/jjlltdnext.desss-portfolio.com.conf` (inside the `:443` VirtualHost).

```bash
sudo cp /etc/apache2/sites-enabled/jjlltdnext.desss-portfolio.com.conf /root/jjlltdnext.conf.bak-$(date +%F)
```

Add these lines **above** the existing catch-all `ProxyPass / http://127.0.0.1:3013/`
(order matters: the API rule must come before `/sentinelops`, because Apache matches by prefix):

```apache
    # SentinelOps API -> Spring Boot (8096); /sentinelops-api/x  ->  /api/x
    ProxyPass        /sentinelops-api  http://127.0.0.1:8096/api
    ProxyPassReverse /sentinelops-api  http://127.0.0.1:8096/api

    # SentinelOps admin -> Next.js (3017), built with basePath /sentinelops
    ProxyPass        /sentinelops  http://127.0.0.1:3017/sentinelops
    ProxyPassReverse /sentinelops  http://127.0.0.1:3017/sentinelops
```

Optional (recommended if the network team agrees): restrict to office/VPN IPs.

```apache
    <Location /sentinelops>
        Require ip 203.0.113.0/24    # replace with the real office/VPN range
    </Location>
    <Location /sentinelops-api>
        Require ip 203.0.113.0/24
    </Location>
```

Validate, then reload (never restart):

```bash
sudo apache2ctl configtest          # must print: Syntax OK
sudo systemctl reload apache2
```

Rollback (if anything looks wrong):

```bash
sudo cp /root/jjlltdnext.conf.bak-<date> /etc/apache2/sites-enabled/jjlltdnext.desss-portfolio.com.conf
sudo apache2ctl configtest && sudo systemctl reload apache2
```

## 7. Verify

- https://jjlltdnext.desss-portfolio.com/sentinelops/status  -> "All systems operational"
- https://jjlltdnext.desss-portfolio.com/sentinelops/login   -> sign in
- Existing site https://jjlltdnext.desss-portfolio.com/ still works.

## 8. Scan engine and Juice Shop lab (Phase 2) - needs Docker, ASK FIRST

Do this only after steps 1-7 work. Tell the network-security person BEFORE the first scan: scans come from this
server's IP, are marked with the header `X-Pentest: sentinelops/<engagement>`, and the first target is our own lab.

Pre-checks (read-only):

```bash
docker --version && docker compose version
docker ps --format '{{.Names}}'                     # what already runs - we touch none of it
docker network ls; docker network inspect $(docker network ls -q) 2>/dev/null | grep -i '"Subnet"'
# 172.28.0.0/24 must NOT appear above. If it does, change the subnet in lab/docker-compose.yml AND sentinelops.scan.lab.cidrs.
```

Who may run Docker: membership of the `docker` group is **root-equivalent**. The backend runs as the user that starts
PM2. Use a dedicated low-privilege user for `sentinelops-backend` if possible (ask the CEO / network person); the
backend only ever runs the fixed command template in `DockerRunner` (no shell, validated inputs).

Start the lab (our own copy of Juice Shop; no published ports; internal network):

```bash
cd /var/www/Vhost/jjlltdnext.desss-portfolio.com
docker compose -f lab/docker-compose.yml up -d     # upload the lab/ folder next to sentinelops_backend first
docker ps --filter name=sentinelops-juice-shop
# The backend resolves the lab host name itself, so give this host that name (one line, harmless):
echo '172.28.0.10 juice-shop' | sudo tee -a /etc/hosts
```

Rollback: `docker compose -f lab/docker-compose.yml down` and remove that `/etc/hosts` line.

Egress control for scans of EXTERNAL targets (strongly recommended, network person): scanner containers use Docker's
bridge and can reach whatever the host can. Create a dedicated network and block private ranges from it, e.g.

```bash
docker network create --subnet 172.29.0.0/24 sentinelops-scan
# DOCKER-USER rules (network person decides how they are persisted): drop traffic from 172.29.0.0/24 to
# 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 and to this server's own addresses.
```

then set `sentinelops.scan.engine.scan-network=sentinelops-scan`. Without such a rule the only protection against a
site redirecting a scanner into the company network is the tool's own behaviour (they stay on the target host by default).

Turn the engine on (application.properties), then restart ONLY the backend:

```
sentinelops.scan.engine.enabled=true
sentinelops.scan.lab.enabled=true
sentinelops.scan.lab.hosts=juice-shop
sentinelops.scan.lab.cidrs=172.28.0.0/24
sentinelops.scan.engine.work-dir=/var/www/Vhost/jjlltdnext.desss-portfolio.com/sentinelops_backend/scan-work
```

```bash
pm2 restart sentinelops-backend            # only this app
docker pull projectdiscovery/nuclei:latest ghcr.io/zaproxy/zaproxy:stable drwetter/testssl.sh:3.2 instrumentisto/nmap:latest
```

First lab run (in the UI, as ADMIN): engagement -> register target `juice-shop` with "lab" ticked and base URL
`http://juice-shop:3000` -> draft authorization covering it (WEB) -> submit -> approve (a second person if four-eyes)
-> Request scan WEB / PASSIVE. Expect two runs (nuclei, zap). Send me the run errors if any fail; the command flags
were written from the tools' documentation and have not run against real containers yet.

Disk: raw output is kept in `scan-work/<run id>/`; delete old folders when no longer needed.
