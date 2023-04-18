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
