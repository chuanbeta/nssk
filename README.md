## 环境配置

python 3.6以上均可

需要安装Crypto库

```
pip install pycryptodome
```

## 部署

client文件夹放在客户端主机，server文件夹放在服务端主机。

然后更改`server.py`（第7行）和`client.py`（第19行）中的S_HOST和S_PORT变量为服务器端的ip地址和提供服务的端口号。

服务器端运行

```
python server.py
```

客户端运行

```
python client.py
```

## 测试

运行测试过程见视频。