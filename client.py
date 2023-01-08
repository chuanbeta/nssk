import json
import socket
from json import dumps, loads
from AES import *
from sys import exit
from random import randint


def send_dict(msg: dict) -> bytes:
    return dumps(msg).encode()


def get_dict(msg: bytes) -> dict:
    return loads(msg.decode())


class Client:
    def __init__(self):
        self.S_HOST = '192.168.1.5'
        self.S_PORT = 8080
        self.userid = None  # 用户名
        self.ip = None  # 绑定的ip
        self.port = None  # 绑定的port
        self.SockWithServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.SockWithClient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.KeyWithServer = None
        self.KeyWithClient = {}
        self.isListening = False  # 是否开启了监听。
        self.id_ip: dict = {}  # 正在监听的用户id-ip映射
        self.id_port: dict = {}  # 正在监听的用户id-port映射

    def run(self):
        try:
            print('\n---------------------------------------------------------\n')
            print("欢迎来到基于NSSK协议的聊天系统！")
            self.connect()
        except KeyboardInterrupt:
            self.shutdown()
        # 到了这里，保证已经登录了
        while True:
            try:
                self.listen_or_talk()
            except KeyboardInterrupt:
                if self.isListening:
                    self.remove()
                    continue
                else:
                    self.shutdown()

    def remove(self):
        self.isListening = False
        send = {'api': 'remove'}
        self.SockWithServer.sendall(send_dict(send))
        print('你 -> 服务器：', send)
        get = get_dict(self.SockWithServer.recv(1024))
        print('服务器 -> 你：', get)
        print('取消监听状态！')

    def connect(self):
        self.SockWithServer.connect((self.S_HOST, self.S_PORT))
        print("连接服务器成功！")
        self.bind()

    def bind(self):
        self.ip = input("请输入你绑定的ip：")
        self.port = int(input("请输入绑定的端口号："))
        self.SockWithClient.bind((self.ip, self.port))
        self.SockWithClient.listen(0)
        self.SockWithClient.settimeout(0.5)
        print("绑定成功！")
        print('\n---------------------------------------------------------\n')
        self.register_or_login()

    def register_or_login(self):
        while True:
            print("请输入数字选择：\n1：注册\n2：登录\n3：退出系统\n")
            choice1 = input("你的选择：")
            print('\n---------------------------------------------------------\n')
            if choice1 == "1":
                print("开始注册~")
                if self._reg_log("REGISTER"):
                    print('\n---------------------------------------------------------\n')
                    break
                else:
                    continue
            elif choice1 == "2":
                print("开始登录~")
                if self._reg_log("LOGIN"):
                    print('\n---------------------------------------------------------\n')
                    break
                else:
                    continue
            elif choice1 == "3":
                self.shutdown()
                break
            else:
                print("输入错误，请重新选择！")

    def _reg_log(self, mode):
        self.userid = input("请输入用户名：")
        password = input("请输入密码：")
        if mode == "REGISTER":
            send = {'api': 'register', 'userid': self.userid, 'password': password}
            self.SockWithServer.sendall(send_dict(send))
            print('你 -> 服务器：', send)
            get = get_dict(self.SockWithServer.recv(1024))
            print('服务器 -> 你：', get)
            if get['msg'] == 'error':
                print('该用户已注册过！')
                return False
            elif get['msg'] == 'succeed':
                # 与服务器的密钥交换省略，直接让服务器发送共享密钥
                self.KeyWithServer = bytes.fromhex(get['key'])
                print('注册成功！')
                return True
        elif mode == "LOGIN":
            send = {'api': 'login', 'userid': self.userid, 'password': password}
            self.SockWithServer.sendall(send_dict(send))
            print('你 -> 服务器：', send)
            get = get_dict(self.SockWithServer.recv(1024))
            print('服务器 -> 你：', get)
            if get['msg'] == 'error':
                print('用户名或密码错误！')
                return False
            elif get['msg'] == 'succeed':
                self.KeyWithServer = bytes.fromhex(get['key'])
                print('登录成功！')
                return True

    def listen_or_talk(self):
        print('请输入数字选择：')
        print('1：监听，你将作为NSSK协议的B端，等待有人向你发送请求')
        print('2：请求聊天，你将作为NSSK协议的A端，向你想聊天的用户发起认证请求，认证通过后就可以聊天了！')
        print('3：退出系统\n')
        choice2 = input('你的选择：')
        if choice2 == "1":
            self.listen()
        elif choice2 == "2":
            self.talk()
        elif choice2 == "3":
            self.shutdown()

    def listen(self):
        # listen是B端，时刻接受A端的请求
        print('\n---------------------------------------------------------\n')
        send = {'api': 'listen', 'ip': self.ip, 'port': self.port}
        self.SockWithServer.sendall(send_dict(send))
        print('你 -> 服务器：', send)
        get = get_dict(self.SockWithServer.recv(1024))
        print('服务器 -> 你：', get)
        self.isListening = True
        print('监听已开启，按ctrl+c退出监听...')
        print('\n---------------------------------------------------------\n')
        while True:
            try:
                conn, address = self.SockWithClient.accept()
            except socket.timeout:
                continue
            print(f'用户{address}连接')
            get = get_dict(conn.recv(1024))
            print('收到：', get)
            print('你收到NSSK协议的第三步,下面将密文解密')
            m = get_dict(aes_de(self.KeyWithServer, bytes.fromhex(get['c'])))
            print(f'解密结果为：{m}')
            Kab = bytes.fromhex(m['Kab'])
            A = m['A']
            print(f'消息来源自称是{A}，和你的密钥是{Kab}，于是你向其发起挑战：')
            print('你发起协议第四步：B->A: {Nb}Kab')
            Nb = randint(1000000, 9999999)
            c = aes_en(Kab, str(Nb).encode())
            send = {'api': 'nssk4', 'c': bytes.hex(c)}
            conn.sendall(send_dict(send))
            print(f'你 -> 自称是{A}的人：', send)
            get = get_dict((conn.recv(1024)))
            print(f'自称是{A}的人 -> 你：', get)
            print('你收到他的应答，并进行验证')
            N = int(aes_de(Kab, bytes.fromhex(get['c'])).decode())
            if N == Nb - 1:
                print(f'验证通过！他确实是{A}！')
                print('开始聊天吧!')
                print('\n---------------------------------------------------------\n')
                send = {'msg': 'beginChat!'}
                conn.sendall(send_dict(send))
            while True:
                try:
                    try:
                        get = get_dict(conn.recv(1024))
                    except json.JSONDecodeError:
                        if self.isListening:
                            self.remove()
                        self.shutdown()
                    m = aes_de(Kab, bytes.fromhex(get['c'])).decode()
                    print(f'{A}：{m}')
                    print('          收到密文：', get['c'])
                    m = input(f'{self.userid}：').encode()
                    c = aes_en(Kab, m)
                    send = {'c': bytes.hex(c)}
                    conn.sendall(send_dict(send))
                    print('          发送密文：', send['c'])
                except socket.timeout:
                    continue

    def talk(self):
        # talk是A端，向B发送请求
        print('\n---------------------------------------------------------\n')
        # 发给服务器想对话的请求，让服务器返回当前开启监听的用户列表
        send = {'api': 'talk'}
        self.SockWithServer.sendall(send_dict(send))
        print('你 -> 服务器：', send)
        get = get_dict(self.SockWithServer.recv(1024))
        print('服务器 -> 你：', get)
        if get['msg'] == 'succeed':
            self.id_ip = get['id_ip']
            self.id_port = get['id_port']
            id_list = [x for x in self.id_ip.keys()]
            list_len = len(id_list)
            print('获取到可建立联系的用户列表！请输入数字选择：\n')
            print('-----------------------------')
            for i in range(list_len):
                print(f'   {i + 1}：与用户->{id_list[i]}<-通信')
            print(f'   {list_len + 1}：更新列表')
            print(f'   {list_len + 2}：返回')
            print(f'   {list_len + 3}：退出系统')
            print('-----------------------------\n')
            choice3 = list_len + 2
            try:
                choice3 = int(input('你的选择：'))  # NSSK中的B的id
            except ValueError:
                print('输入错误！请重试！')
                self.talk()
            if choice3 == list_len + 1:
                self.talk()
            elif choice3 == list_len + 2:
                self.listen_or_talk()
            elif choice3 == list_len + 3:
                self.shutdown()
            else:
                B_id = id_list[choice3 - 1]
                # NSSK协议
                print('\n---------------------------------------------------------\n')
                print(f'开始NSSK协议，验证你和{B_id}的身份！')
                print('--------------------------------')
                print('你发出第一步：A->S: A, B, Na')
                Na = randint(1000000, 9999999)
                send = {'api': 'nssk1', 'msg': {'A': self.userid, 'B': B_id, 'Na': Na}}
                self.SockWithServer.sendall(send_dict(send))
                print('你 -> 服务器：', send)
                get = get_dict(self.SockWithServer.recv(1024))
                print('--------------------------------')
                print('服务器 -> 你：', get)
                print('你收到第二步：S->A: { Na, B, Kab, {Kab, A}_Kbs }_Kas')
                m = get_dict(aes_de(self.KeyWithServer, bytes.fromhex(get['c'])))
                print(f'解密第二步的消息，得到：{m}')
                Kab = bytes.fromhex(m['Kab'])
                print(f'你得到了和{B_id}的共享密钥，为{Kab}')
                SockWithB = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                SockWithB.connect((self.id_ip[B_id], self.id_port[B_id]))
                print('--------------------------------')
                print('你发起第三步：A->B: {Kab, A}_Kbs')
                send = {'api': 'nssk3', 'c': m['c1']}
                SockWithB.sendall(send_dict(send))
                print(f'你 -> {B_id}：', send)
                get = get_dict(SockWithB.recv(1024))
                print(f'{B_id} -> 你：', get)
                print('--------------------------------')
                print('你收到第四步：B->A: {Nb}_Kab')
                print('现在你接受挑战，解出Nb')
                Nb = int(aes_de(Kab, bytes.fromhex(get['c'])).decode())
                print(f'你解出来的Nb为{Nb}，接下来你将Nb-1发给{B_id}')
                print('--------------------------------')
                print('你发起第五步：A->B: {Nb-1}_Kab')
                c = aes_en(Kab, str(Nb - 1).encode())
                send = {'api': 'nssk5', 'c': bytes.hex(c)}
                SockWithB.sendall(send_dict(send))
                print(f'你 -> {B_id}：', send)
                get = get_dict(SockWithB.recv(1024))
                print(f'{B_id} -> 你：', get)
                print('NSSK结束，你们成功交换了密钥，接下来开始聊天吧！')
                print('\n---------------------------------------------------------\n')
                while True:
                    m = input(f'{self.userid}：').encode()
                    c = aes_en(Kab, m)
                    send = {'c': bytes.hex(c)}
                    SockWithB.sendall(send_dict(send))
                    print('          发送密文：', send['c'])
                    try:
                        get = get_dict(SockWithB.recv(1024))
                    except json.JSONDecodeError:
                        if self.isListening:
                            self.remove()
                        self.shutdown()
                    m = aes_de(Kab, bytes.fromhex(get['c'])).decode()
                    print(f'{B_id}:{m}')
                    print('          收到密文：', get['c'])

        else:
            print('talk 错误！')
            self.listen_or_talk()

    def shutdown(self):
        print('\n\n---------------------------------------------------------\n')
        send = {'api': 'logout'}
        self.SockWithServer.sendall(send_dict(send))
        print('你 -> 服务器：', send)
        get = get_dict(self.SockWithServer.recv(1024))
        print('服务器 -> 你：', get)
        self.SockWithClient.close()
        self.SockWithServer.close()
        print('再见！')
        print('\n---------------------------------------------------------\n')
        exit(0)


if __name__ == '__main__':
    talk_client = Client()
    talk_client.run()
