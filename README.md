# suway-ng
sudo/su commands with xwayland display fixes 


this tool is on the early phase... and the first Beta version ( v0.95) 

-- Please report issues or pull requests to support this tool!


g++ suway-ng.cpp -o suway-ng -lX11 -lXau -lcrypto


deps

sudo pacman -Syu xorg-x11 xorg-xauth openssl
