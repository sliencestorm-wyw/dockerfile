# dockerfile
dockerfile文件

 docker run -P  -d  --name  ssh ssh:v1  /usr/sbin/init
 
 docker run -p host_port:docker_port  -d  --name  ssh ssh:v1  /usr/sbin/init
 
 #such as webconsole
 
 docker run -d -p 8080:8080 --restart=always --name webconsole webconsole:latest
