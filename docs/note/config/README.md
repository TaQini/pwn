
# docker



## 定时执行任务
修改`start.sh`,结尾添加循环:

```bash
while :
do 
rm -rf /home/ctf/tmp/*
sleep 60
done
#sleep infinity & wait\
```

## ulimit config
配置ulimit，在`start.sh` 文件中加入如下内容：

```bash
echo ulimit -n 1024 >> /etc/profile
echo "*      hard     nofile     1024" >> /etc/security/limits.conf
```
