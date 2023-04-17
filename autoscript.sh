#!/bin/bash

while true; do
  echo "Which script do you want to run?"
  echo "1) Auto config script"
  echo "2) Auto config script for iran VPS (Does not work)"
  echo "3) Hardening"
  echo "4) Delete all DNS records"
  echo "5) set A record"
  echo "6) Get cert from CF"
  echo "7) Set CF SSL/TLS Full"
  echo "8) exit"
  read -p "Enter your choice: " choice

  if [ $choice -eq 1 ]; then
read -p "Enter domain name and extension (e.g. example.com): " domain
locale-gen en_US.UTF-8
update-locale LANG=en_US.UTF-8
apt update -y && apt install nginx vim rsync net-tools curl wget jq vnstat htop sshpass -y
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
systemctl enable v2ray && systemctl enable nginx
crontab -l | { cat; echo "0 0 * * 0 rm -rf /usr/local/etc/v2ray/vaccess.log && rm -rf /usr/local/etc/v2ray/verror.log"; } | crontab -

cd /root/

mv lhsconfigfiles/config.json /usr/local/etc/v2ray/config.json
mv lhsconfigfiles/server /root/ && chmod +x server
mv lhsconfigfiles/.env /root/
mv lhsconfigfiles/web.service /lib/systemd/system/web.service
rm -rf /etc/nginx/conf.d/*.conf

nginx_CONF=$(
    cat <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name *.${domain};
    charset utf-8;
}
server {
    listen       443 ssl http2;
    listen       [::]:443 ssl http2;
    server_name  *.${domain};
    charset utf-8;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:TLS13-AES-128-CCM-8-SHA256:TLS13-AES-128-CCM-SHA256:EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache builtin:1000 shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_buffer_size 1400;
    ssl_session_tickets off;
    ssl_certificate /root/cert/fullchain.pem;
    ssl_certificate_key /root/cert/private.key;
    root /usr/share/nginx/html;
    location /ws {
      proxy_redirect off;
      proxy_pass http://127.0.0.1:10001;
      proxy_http_version 1.1;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host \$host;
      # Show real IP in v2ray access.log
      proxy_set_header X-Real-IP \$remote_addr;
      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
)

echo "${nginx_CONF}" >/etc/nginx/conf.d/${domain}.conf

v2ray_Service=$(
    cat <<EOF
[Unit]
Description=V2Ray Service
Documentation=https://www.v2fly.org/
After=network.target nss-lookup.target
[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/v2ray run -config /usr/local/etc/v2ray/config.json
Restart=on-failure
RestartPreventExitStatus=23
[Install]
WantedBy=multi-user.target
EOF
)

echo "${v2ray_Service}" >/etc/systemd/system/v2ray.service
mkdir /var/log/webs
systemctl daemon-reload && systemctl restart v2ray && systemctl enable web.service && systemctl start web.service && systemctl restart nginx
echo "Install Done!"

    read -p "Do you want to continue? [y/n]: " continue
    if [ "$continue" == "n" ]; then
      break
    fi

  elif [ $choice -eq 2 ]; then

locale-gen en_US.UTF-8
update-locale LANG=en_US.UTF-8
apt update -y && apt install vim rsync net-tools curl wget vnstat htop sshpass -y
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)

read -p "Enter remote password: " remote_pass
cd /root/

sshpass -p 'qrsUFX238' scp root@157.90.0.90:/root/lhsconfigfiles/iran/config.json /usr/local/etc/v2ray/

sshpass -p 'qrsUFX238' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r root@157.90.0.90:/root/lhsconfigfiles/server /root/
sshpass -p 'qrsUFX238' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r root@157.90.0.90:/root/lhsconfigfiles/.env /root/
sshpass -p 'qrsUFX238' scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -r root@157.90.0.90:/root/lhsconfigfiles/web.service /lib/systemd/system/web.service


v2ray_Service=$(
    cat <<EOF
[Unit]
Description=V2Ray Service
Documentation=https://www.v2fly.org/
After=network.target nss-lookup.target
[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/v2ray run -config /usr/local/etc/v2ray/config.json
Restart=on-failure
RestartPreventExitStatus=23
[Install]
WantedBy=multi-user.target
EOF
)

echo "${v2ray_Service}" >/etc/systemd/system/v2ray.service
cd /root/
chmod +x server
mkdir /var/log/webs
systemctl daemon-reload && systemctl restart v2ray && systemctl restart v2ray && systemctl enable web.service && systemctl start web.service
echo "Install Done!"

    read -p "Do you want to continue? [y/n]: " continue
    if [ "$continue" == "n" ]; then
      break
    fi

  elif [ $choice -eq 3 ]; then

sudo apt update
sudo apt upgrade -y

sudo apt install fail2ban -y

sudo adduser --disabled-password --gecos "" lhs

sudo usermod -aG sudo lhs

echo "lhs     ALL=(ALL)     NOPASSWD:ALL" | sudo tee -a /etc/sudoers

su lhs << EOF
cd /home/lhs
mkdir .ssh
chmod 755 .ssh
exit
EOF

sudo apt install ufw -y
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw allow 2053
sudo ufw allow 3000
read -p "Do you need 56777 port? Y/N: " answer
if [ "$answer" == "y" ] || [ "$answer" == "Y" ]; then
  ufw allow 56777
fi
sudo ufw enable
sudo ufw reload

sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure unattended-upgrades

sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo service ssh restart

echo "Match User root,lhs" >> /etc/ssh/sshd_config
echo "           PasswordAuthentication no" >> /etc/ssh/sshd_config
sudo service ssh restart

sudo apt install apparmor apparmor-utils -y
sudo aa-enforce /etc/apparmor.d/*

echo "Welcome to $(hostname)" | sudo tee /etc/issue.net

mkdir -p /home/lhs/.ssh

touch /home/lhs/.ssh/authorized_keys

echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCah7B06XyodjT00Bxde7IR9gcYz2GEremDTzQ0bi9DU3WtykaUiV9oR3xDXJj73RzLldrtt3Rc0XpvnJNRqnPfc6soPBgMhCoiG5Sx18Ivk2bGULJlg5oxcq2SuawjuEZJrRrKMfqhA967c0cpbvlejkk3ycOqm3O8vZNx9fn40gUX9C5jzPWp1KfJyzY+x5m/bNgjXQbKBHlDP3I+AASgF7qNjGUHzoBNN4EGpS0oMYIMdlRnFkzhfkiBWFNxZZJDMVeYWAb7MmLt22HxnVPGw3L0G/tPnQ1XVqwke/bfTunRZLigi/few/Clz0vQS+p+UaZRmQutSh9lAlgGGin3gzheXfbxyzdUA+qFBN056fjJ/tCw9poJYftkFwIspGf5QozeCAdaZ6XynEUZr4PmaJkfGJqIpfvoettIhoHgjingAiLmb74mCoQtugfCHl/t1MsTCto7b1ng84c/JVd5R4zOIzwVM0Fl3SGFrZCLRfHgg4ALBiure/mnDN150AE= joniur@itsjoniur" >> /home/lhs/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCHLxb6MSI1pRDQEo6a2uBOaYB/Ye2wjXyT9OFjFdp3DcZPdwWJ3dag/fpNBTHoscjmMDBVOvqy46f27KdD0CbVLkBAu2fVeP9eQ7xXAPWAhF2J94zrNH7Xs8wxI5b2pfT06OrtYwe/AQnCe9oQdJV5gcS7Hfys0HoiGgQks9tppyZVdCJg0vEpDn0RV6cHZDXhMfmJYp6s/H3ku+KWZtVCE0kBQTkQu8Lb3ITUuGYTBeMWY6XNvPKh1ETlQb/VIV463B/kiDc9Qz3NRQGsXKTbm73DrXXJzak6Q5tq02TZEaqffu5SYLO7xsRY6STNJe+r19hZo6ih9kznGrmrKWdn rsa-key-20230114" >> /home/lhs/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCZcRAEoWP6nBjg/jA4BxxQy7DZm4uqeSGU/e7ujEoI1VzFEcfPK2hUkqGdwoqHU5p6u03PI8eUyMf27qqB/DFV6LejCV6qM3Hr6qX7XmvVfzmQ7ejwdUIOerAZiTBefv7HejK3mXoF3E9QZ++/Ybj46oap0pDz4nmpf2RkTVXamWzALERf9HOoYMpA4NcBSNsvvWgPsJ/8ttf6LZEEVCwzO8aWvmaZUGhoYn75qvD9FHLhLkpkafHSHazBDTrnPjcYdDvwwSnb8pip9mOGjdJ18dARbt6rAnOgvMe1GC5GYM7qm5hx2EcCqbAeS10eTEeYNjsOmBC5ZOPgNTkvbs24n6YsyFcCZNcVDn4buCDjiWshwY5llFQAC2duS4zk+CN0DOBeplSMWpt6VQlPHwFv9sYtiAMPxDCEPLiu+iitpv6goGhNShwbesRfCIYalhv3KycF3Fpsctl6854BgRo/rAXLzSsGPySNi1qIqVaWqcv6U92wITEcF243A0AZ3sc= amir@arcmir" >> /home/lhs/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9Eb73YqMGrNqBheBWn/PGWw7UISnLA1EGc5wjB0FA84GBlAiX/D/MsBYfy1icmR1AYihgc+Eu+Ehetp5M66apCVm5M7Dyixdulzfp0HfESMOScuzvsHTz7FyAZkH1kgcMRU6bC4OA36j13/TG7IXUhCmXl6KpKAnm4s8lse/9LjkrwZjMuL26jpo/q5Nl5JnrUAo9iTJqIJGxLAGXuU7iWiVSz1B94rBndZDjL6pUsQ9USIwj7Q3b3LfD4hPGtQhbBkcLMXqw2b8wqw3jf8joX56Ol37EmGhzRllc+1JRDL0yI9kBjEpYKHuPLL1BHBEEF3nC48uh9V6wpceNcba0/pePB6B+BEuyhYKbEnZSKuL1PTbwDKWwHCWhp7aHPm/8ivKnVkQa+8YPMKucOS3kYa4VmC2OwP49QLQ/zcD0oLedKR3DJXYRT7lopHaR06Lca5yM0IdRM9Q1a2e46m5iVtmgUKSJS2J/ywcALs/Ihy3FpAzy6T79FHt+EI1JeYk= root@srv1675427914.hosttoname.com" >> /home/lhs/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDJNAa6dWnRbEu7a1NW7HrG5Tn3EpqvOOAULX26Vzb0PgGLawGquMXwwYedHhGD2E3kbvoJv58Vt+ODw2akX/MtAQx4mCD6IDkr6SX4/9AHQeVlb+5R/BCeAWmwQetUf1dzk4g7xEvjHT6FZXAbQ3MaKv0Q5gWPgWb/fMbTSS0tvvytLc8wpha3baK1XCvcoMvC/vXX9Zny+ibr2PcGZY+FWSCmq1nJtB/KfUzxnupxYtUoE33IC7q9h4O9pq11s6NA4QSm9pYvvFNG/zt+tM6tw7E+w4ZobtJYgKEz8d/PwTo5F4wV6Fhv+YN3aMi47iHNfCdOKS/RtahFuh7QTy+11KUoaFp5uRdgSxFCOtYOjq79CutU/R+H0toHSeiZpqF7Ljpfl61n27ysVQ/7SKfsfrZi7e2KFGyZ/ud1gF3vKkJ2UMicD0SKrMxiFQ1Px0Ucz1bDnzC7N/hk8q/lHex6M+AiN1f8TD9Ie3FB0iqIHSPcokEVODdZc6/PKB5k5aE= ahmad@develozer" >> /home/lhs/.ssh/authorized_keys
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDiLzEdAs2Ux0+qy5IIz4tctJliVQPKOV+/yOodrPdoedaUEZ4NV2F2yng8NThL6OVGn9lc1fRL9FbadeSu37uxQDgCUMTGwzbmih7ef3zuA1pFWgmrb39soQEu1j70No4hR4R42xL6wrDQjkL6DDvNvaPC+Dh5hBj3ptumd+IKigezPG03rPg5gc1P1Uy74QhIpYaip+W+cre5yWKbe8NtLYU6uF7fhVs4zz7Q9F/pZEfRebSVLr1xPqbgqKe6lzDWUFT9PymVgeoAr9zwJjftgZ7mH75UuknjGLh0oC3BTTitXAnbB35nLi0S0tBpT4a93ksiH/tFEi93bU96CtayF2mrjXyPdfaqzlxh8ya4x8LdBKQfZs4JUh4hAQH47C5XZ44czTSHmFIMl96HJzUHPXoya/Zb2kEDB7SMUc6DJ9sBFNFyL6FRy8clO2F/SLFJx8Jn9j+7ewkMUtBDntn5w7DefMnHXZK07+3meoF4rBHmzCMR36guJkN05l6jg6U= mohamad@Mohamads-MacBook-Pro.local" >> /home/lhs/.ssh/authorized_keys
echo "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBACsRqSiiKJXanUAn/982gjVaOHh0hvrGFYRAICsiTmxhHc5jvfoXMcotyHZhjw2eoztYqv5G4NJA4rHv6ZzFZr5yABXFLG2tTuruMygaQgvF+EQSga1Xti1fM9JBIqyDIJ1zMcN8t1qXIm/qJYar3wogKqnsatCzijFcfRz7xgOpyXtYQ== amir@arcmir" >> /home/lhs/.ssh/authorized_keys
echo "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAETzfKSw1ADqy3vScwINpiAn0p37yW9svl76BYCodyFQhvwFaif75AtnP2N31X+JIpZ/aRqd5kyptIKWhrDm5X7BgHt2FyfIXJu60L+r+qOuVNmONUMJu+yshOxpTKId4rJf6mgdrVlNkKWiyxkIub7roXgxkjVpppZceA+dOtR/sfNiw== amir@arc" >> /home/lhs/.ssh/authorized_keys

echo "Hardening Done!"

    read -p "Do you want to continue? [y/n]: " continue
    if [ "$continue" == "n" ]; then
      break
    fi

  elif [ $choice -eq 4 ]; then

  read -p "Enter domain name and extension (e.g. example.com): " domain
  python3 /root/lhsconfigfiles/delete_dns.py $domain

    read -p "Do you want to continue? [y/n]: " continue
    if [ "$continue" == "n" ]; then
      break
    fi  

  elif [ $choice -eq 5 ]; then
  
  read -p "Enter domain name and extension (e.g. example.com): " domain
  read -p "Enter VPS IP (e.g. 127.0.0.1 - Our home): " ip
  python3 /root/lhsconfigfiles/cflare --set-record -H $domain -a $ip

    read -p "Do you want to continue? [y/n]: " continue
    if [ "$continue" == "n" ]; then
      break
    fi
  
  elif [ $choice -eq 6 ]; then

  read -p "Enter domain name and extension (e.g. example.com): " domain
  python3 /root/lhsconfigfiles/cflare --gen-cert -H $domain
  cd /root/lhsconfigfiles
  rm -rf /root/cert
  mkdir /root/cert/
  mv fullchain.pem /root/cert/ && mv private.key /root/cert/
  
    read -p "Do you want to continue? [y/n]: " continue
    if [ "$continue" == "n" ]; then
      break
    fi

  elif [ $choice -eq 7 ]; then 

  read -p "Enter domain name and extension (e.g. example.com): " domain
  python3 /root/lhsconfigfiles/ssltls.py $domain

    read -p "Do you want to continue? [y/n]: " continue
    if [ "$continue" == "n" ]; then
      break
    fi

  elif [ $choice -eq 8 ]; then
    echo "Exiting the script."
    break
  else
    echo "Invalid choice"
  fi
done
