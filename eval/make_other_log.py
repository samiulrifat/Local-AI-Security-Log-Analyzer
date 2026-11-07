"""Writes a test log in a different format with different attackers (nginx access
lines mixed with sshd lines), to check the app isn't fitted to the supplied log."""
import random
from datetime import datetime, timedelta

random.seed(11)
start = datetime(2026, 3, 2, 14, 0, 0)
lines = []
when = start


def access(ip, method, path, status, agent="Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0", size=None):
    stamp = when.strftime("%d/%b/%Y:%H:%M:%S +0000")
    size = size or random.randint(200, 9000)
    lines.append(f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"')


def ssh(text):
    lines.append(f"{when.strftime('%b %d %H:%M:%S')} web01 sshd[{random.randint(1000, 9999)}]: {text}")


PAGES = ["/", "/products", "/products/12", "/cart", "/about", "/static/site.css", "/static/app.js"]
for i in range(320):
    when += timedelta(seconds=random.randint(5, 40))
    access(f"172.16.{random.randint(1, 3)}.{random.randint(2, 60)}", "GET", random.choice(PAGES),
           random.choice([200, 200, 200, 200, 304, 404]))

    # ssh brute force on root from one address, spread through the file, then it gets in
    if i in (10, 40, 70, 95, 130, 170, 200, 240):
        ssh("Failed password for root from 45.33.12.9 port 51122 ssh2")
    if i == 280:
        ssh("Accepted password for root from 45.33.12.9 port 51130 ssh2")

    # someone mistypes once, not an attack
    if i == 150:
        ssh("Failed password for deploy from 172.16.1.20 port 40022 ssh2")
    if i == 151:
        ssh("Accepted password for deploy from 172.16.1.20 port 40022 ssh2")

    # sql injection through the search box
    if i in (60, 62, 250):
        access("91.200.4.7", "GET", "/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--", 500, "sqlmap/1.8")

    # scanner
    if 100 <= i <= 108:
        path = ["/wp-login.php", "/.env", "/.git/HEAD", "/phpmyadmin/", "/admin.php", "/config.php",
                "/backup.sql", "/cgi-bin/test", "/.aws/credentials"][i - 100]
        access("185.77.2.3", "GET", path, 404, "Nikto/2.5")

    # app server falling over for a moment, normal errors
    if i in (210, 211, 212):
        access("172.16.2.8", "GET", "/products/12", 502)
        lines.append(f"{when.strftime('%Y/%m/%d %H:%M:%S')} [error] 88#88: upstream timed out while connecting to upstream")

with open("samples/other_format.log", "w") as f:
    f.write("\n".join(lines) + "\n")
print(len(lines), "lines")
