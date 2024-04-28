# privatechat
$ python3 server.py --help
Использование: server.py [-h] [--host HOST] [--port PORT] [--key KEY] [--loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [--logfile LOGFILE]

Запустить чат сервера.

Настройки:
  -h, --help            Показать это справочное сообщение и выйти.
  --host HOST           IP-адрес, к которому будет привязан сервер. (По умолчанию=0.0.0.0)
  --port PORT           Номер порта, к которому будет привязан сервер. (По умолчанию=12345)
  --key KEY             Секретный ключ для шифрования. (По умолчанию=mysecretpassword)
  --loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Установить уровень ведения журнала (По умолчанию: INFO)
  --logfile LOGFILE     Задать имя файла журнала. (По умолчанию: server.log)
--------------------------------------------------------------------------
$ python3 client.py --help
Использование: client.py [-h] [--host HOST] [--port PORT] [--key KEY]

Подключиться к чату сервера.

Настройки:
  -h, --help            Показать это справочное сообщение и выйти.
  --host HOST           IP-адрес, к которому будет привязан сервер. (По умолчанию=0.0.0.0)
  --port PORT           Номер порта, к которому будет привязан сервер. (По умолчанию=12345)
  --key KEY             Секретный ключ для шифрования. (По умолчанию=mysecretpassword)
  
  Шифрование - sha256, fernet, base64
