from socketserver import BaseRequestHandler, ThreadingTCPServer

from AES import get_key, aes_en
from json import loads, dumps

# 服务器的绑定的ip和端口，定死的
S_HOST, S_PORT = '192.168.1.5', 8080
# 在线人数
online_num = 0
# 用户名-密码映射
id_pass = {}
# 开启监听者列表，监听者在NSSK协议里是B端
id_ip, id_port ={}, {}
# 密钥列表，所有的键值表示已注册的所有用户
id_key = {}


def send_dict(msg: dict) -> bytes:
    return dumps(msg).encode()


def get_dict(msg: bytes) -> dict:
    return loads(msg.decode())


class Handler(BaseRequestHandler):

    def handle(self) -> None:
        global online_num, id_ip, id_pass
        address, port = self.client_address
        userid = ''
        key = b''
        print(f'{address}:{port} 已连接')
        online_num += 1
        print(f'当前在线人数：{online_num}')
        while True:
            get = get_dict(self.request.recv(1024))
            print(f'收到：{address}:{port}', get)
            if get['api'] == 'register':
                userid = get['userid']
                # 用户已存在
                if userid in id_pass.keys():
                    send = {'msg': 'error'}
                    self.request.sendall(send_dict(send))
                    print(f'发出：{address}:{port}', send)
                else:
                    key = get_key()
                    id_pass[userid] = get['password']
                    id_key[userid] = key # 保存密钥
                    send = {'msg': 'succeed', 'key': bytes.hex(key)}
                    self.request.sendall(send_dict(send))
                    print(f'发出：{address}:{port}', send)
            elif get['api'] == 'login':
                userid = get['userid']
                # 用户名错
                if userid not in id_key.keys():
                    send = {'msg': 'error'}
                    self.request.sendall(send_dict(send))
                    print(f'发出：{address}:{port}', send)
                # 密码错
                elif id_pass[userid] != get['password']:
                    send = {'msg': 'error'}
                    self.request.sendall(send_dict(send))
                    print(f'发出：{address}:{port}', send)
                else:
                    key = id_key[userid]
                    id_pass[userid] = get['password']
                    send = {'msg': 'succeed', 'key': bytes.hex(key)}
                    self.request.sendall(send_dict(send))
                    print(f'发出：{address}:{port}', send)
            elif get['api'] == 'logout':
                print(f'{address}:{port}退出登录')
                send = {'msg': 'succeed'}
                self.request.sendall(send_dict(send))
                print(f'发出：{address}:{port}', send)
                online_num -= 1
                print(f'当前在线人数：{online_num}')
                break
            elif get['api'] == 'listen':
                # 加入监听者名单
                id_ip[userid] = get['ip']
                id_port[userid] = get['port']
                send = {'msg': 'succeed'}
                self.request.sendall(send_dict(send))
                print(f'发出：{address}:{port}', send)
            elif get['api'] == 'remove':
                # 移出监听者名单
                id_ip.pop(userid)
                id_port.pop(userid)
                send = {'msg': 'succeed'}
                self.request.sendall(send_dict(send))
                print(f'发出：{address}:{port}', send)
            elif get['api'] == 'talk':
                # 返回监听者名单
                send = {'msg': 'succeed', 'id_ip': id_ip, 'id_port': id_port}
                self.request.sendall(send_dict(send))
                print(f'发出：{address}:{port}', send)
            elif get['api'] == 'nssk1':
                A = get['msg']['A']
                B = get['msg']['B']
                Na = get['msg']['Na']
                Kab = bytes.hex(get_key()) # A和B的共享密钥
                m1 = {'Kab': Kab, 'A': A}
                c1 = aes_en(id_key[B], send_dict(m1))
                m = {'Na': Na, 'B': B, 'Kab': Kab, 'c1': bytes.hex(c1)}
                c = aes_en(id_key[A], send_dict(m))
                print('------------------------------\n')
                print('收到协议第一步，发送协议第二步')
                print(f'm1 = {m1}')
                print(f'加密后：c1 = {c1}')
                print(f'm = {m}')
                print(f'加密后：c = {c}')
                send = {'msg': 'nssk2', 'c': bytes.hex(c)}
                self.request.sendall(send_dict(send))
                print(f'发出：{address}:{port}', send)
                print('协议第二步完成\n')
                print('------------------------------')


if __name__ == '__main__':
    server = ThreadingTCPServer((S_HOST, S_PORT), Handler)
    print("Listening")
    server.serve_forever()
    a = {'a': 1, 'b': 'ffa'}
    b = dumps(a).encode()
    print(b)
    c = loads(b.decode())
    print(c)
