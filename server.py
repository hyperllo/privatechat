import socket
import base64
import hashlib
import logging
import argparse
import threading
from datetime import datetime

import cryptography.fernet
from cryptography.fernet import Fernet
from colorama import init, Fore, Style

init(autoreset=True)

clients = {}
clients_lock = threading.Lock()

def log_setup(loglevel, logfile):
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Неверный уровень журнала: {loglevel}")

    logging.basicConfig(level=numeric_level,
                        format="%(asctime)s [%(levelname)s] - %(message)s",
                        handlers=[logging.FileHandler(logfile),
                                  logging.StreamHandler()])

class ClientHandler(threading.Thread):
    def __init__(self, client_socket):
        threading.Thread.__init__(self)
        self.client_socket = client_socket
        self.username = None

    def run(self):
        global clients

        while True:
            try:
                encrypted_prompt = cipher.encrypt("Введите имя пользователя: ".encode('utf-8'))
                self.client_socket.send(encrypted_prompt)
                encrypted_username = self.client_socket.recv(1024)
                username = cipher.decrypt(encrypted_username).decode('utf-8').strip()
                with clients_lock:
                    if username in clients or not username:
                        encrypted_error_msg = cipher.encrypt(
                            "Это имя пользователя уже занято или недействительно. Пожалуйста введите другое имя.".encode('utf-8')
                        )
                        self.client_socket.send(encrypted_error_msg)
                        continue
                    else:
                        self.username = username
                        clients[self.username] = self.client_socket
                        encrypted_success_msg = cipher.encrypt("Имя пользователя успешно установлено.".encode('utf-8'))
                        self.client_socket.send(encrypted_success_msg)
                        break
            except cryptography.fernet.InvalidToken:
                print(Fore.RED + f"Ошибка клиента: ключ шифрования недействителен или данные повреждены.")
                logging.info("Ошибка клиента: ключ шифрования недействителен или данные повреждены.")
                continue
            except OSError as e:
                    print(f"Ошибка: {e}")
                    logging.info(f"Ошибка: {e}")
            except BrokenPipeError as e:
                print(f"Произошла неизвестная ошибка: {e}")
                logging.info(f"Произошла неизвестная ошибка: {e}")
            return

        try:
            while True:
                encrypted_message = self.client_socket.recv(1024)
                message = cipher.decrypt(encrypted_message).decode('utf-8')

                if message == "/userlist":
                    with clients_lock:
                        userlist = "\n".join([f"\t{i + 1}) {user}" for i, user in enumerate(clients.keys())])
                        encrypted_response = cipher.encrypt(f"Подключенные пользователи:\n{userlist}".encode('utf-8'))
                        self.client_socket.send(encrypted_response)
                        continue
                if message == "/help":
                    response = Fore.BLUE + "Help Menu:\n" \
                                          "\t/help                           -> Это меню.\n" \
                                          "\t/exit                           -> Выйти из программы.\n" \
                                          "\t/clear                          -> Очистить чат.\n" \
                                          "\t/userlist                       -> Просмотреть список подключенных пользователей.\n" \
                                          "\t/dm [имя_пользователя] [сообщение]            -> Отправить личное сообщение пользователю.\n" \
                                          "\t/changeuser [новое_имя]      -> Изменить имя пользователя.\n"
                    encrypted_response = cipher.encrypt(response.encode('utf-8'))
                    self.client_socket.send(encrypted_response)
                    continue
                if message.startswith("/changeuser "):
                    _, new_username = message.split()
                    with clients_lock:
                        if new_username in clients:
                            encrypted_error = cipher.encrypt(
                                "Это имя пользователя уже занято. Пожалуйста, выберите другое.".encode('utf-8'))
                            self.client_socket.send(encrypted_error)
                        else:
                            del clients[self.username]
                            self.username = new_username
                            clients[self.username] = self.client_socket
                            encrypted_success = cipher.encrypt(f"Имя пользователя изменено на {new_username}.".encode('utf-8'))
                            self.client_socket.send(encrypted_success)
                    continue
                if message.startswith("/dm "):
                    _, recipient, *dm_msg_parts = message.split()
                    dm_message = " ".join(dm_msg_parts)
                    with clients_lock:
                        if recipient in clients:
                            clients[recipient].send(cipher.encrypt(f"[ЛС от {self.username}] {dm_message}".encode('utf-8')))
                            self.client_socket.send(cipher.encrypt(f"[ЛС пользователю {recipient}] {dm_message}".encode('utf-8')))
                        else:
                            encrypted_error = cipher.encrypt("Указанный пользователь не найден.".encode('utf-8'))
                            self.client_socket.send(encrypted_error)
                    continue

                if message == "/clear":
                    encrypted_command = cipher.encrypt("/clear".encode("utf-8"))
                    self.client_socket.send(encrypted_command)
                    continue



                if not message or message == "/exit":
                    logging.info(f"Exit {message}")
                    break
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                broadcast_message = f"[{current_time}] {self.username}: {message}"
                encrypted_broadcast = cipher.encrypt(broadcast_message.encode('utf-8'))
                with clients_lock:
                    for usr, client in clients.items():
                        if usr != self.username:
                            client.send(encrypted_broadcast)
        except:
            pass

        with clients_lock:
            del clients[self.username]
            logging.info(f"Пользователь покинул чат: {username}")
        self.client_socket.close()

def start_server(host, port):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        host_ip, host_port = server_socket.getsockname()
        server_socket.listen(5)
        print("Сервер запущен..")
        print(f"{Fore.YELLOW}Информация о хосте: {Style.RESET_ALL}{host_ip}:{host_port}")
        print(f"{Fore.YELLOW}Ключ по умолчанию    : {Style.RESET_ALL}{str(password)}")
        print(f"{Fore.YELLOW}Fernet ключ      : {Style.RESET_ALL}{str(fernet_key)}")
        logging.info(f"Сервер запущен на {host_ip}:{host_port}")

        while True:
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            client_socket, client_address = server_socket.accept()
            print(f"[{current_time}] {client_address} Подключен.")
            logging.info(f"Принято соединение от {client_address}")
            handler = ClientHandler(client_socket)
            handler.start()
    except cryptography.fernet.InvalidToken:
        print(f"{Fore.RED}Неправильный ключ:{Style.RESET_ALL} [{current_time}] {client_address}")
        logging.error(f"Неверный токен для {client_address}")
        pass
    except OSError as e:
        print(f"Произошла ошибка при запуске сервера: {e}")
        logging.error(f"Произошла ошибка: {e}")
    except KeyboardInterrupt:
        print("Программа завершена.....")
        logging.info("Сервер был завершен из-за прерывания клавиатуры")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Запустить чат сервера.")
    parser.add_argument("--host", default="0.0.0.0", help="IP-адрес, к которому будет привязан сервер. (Default=0.0.0.0)")
    parser.add_argument("--port", type=int, default=12345, help="Номер порта, к которому будет привязан сервер. (Default=12345)")
    parser.add_argument("--key", default="mysecretpassword", help="Секретный ключ для шифрования. (Default=mysecretpassword)")
    parser.add_argument("--loglevel", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],help="Установите уровень ведения журнала (Default: INFO)")
    parser.add_argument("--logfile", default="server.log", help="Установить имя файла журнала. (Default: server.log)")
    args = parser.parse_args()

    password = args.key.encode()
    key = hashlib.sha256(password).digest()
    fernet_key = base64.urlsafe_b64encode(key)
    cipher = Fernet(fernet_key)

    log_setup(args.loglevel, args.logfile)
    start_server(args.host, args.port)
