# PAM Telegram MFA

## Build
```bash
gcc -fPIC -lcurl -lconfig -ljson-c -fno-stack-protector -c pam_telegram.c -o pam_telegram.o
sudo ld -lcurl -lconfig -ljson-c -x --shared -o /lib/security/pam_telegram.so pam_telegram.o
```

## PAM
```
# For testing:
auth        optional    pam_telegram.so [/path/to/pam_telegram.cfg]

# Production:
auth        required    pam_telegram.so [/path/to/pam_telegram.cfg]
```

## Configuration
Default configuration location: /etc/pam_telegram.cfg

## SELinux
When you are running SELinux, maybe you have to set the bool ssh_can_network to true:
```bash
setsebool -P ssh_can_network 1
```