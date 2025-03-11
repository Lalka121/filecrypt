# filecrypt
Простое CLI-приложение для хеширования и дехеширования файлов при помощи алгоритма AES

#### Функционал:
1. Генерация случайного ключа
2. Хеширование файла при помощи того или иного ключа
3. Дехеширование файла, полученного в результате предыдущего пункта

## Установка
### С помощью Go
Выполните команду, приведённую ниже. Файл установиться в `$GOPATH/bin`
```
go install github.com/Lalka121/filecrypt@latest
```

### С помощью git
Сначала необходимо клонировать репозиторий, а после настроить переменную окружения `PATH`.
#### Windows:
Для начала зажмите сочетание клавиш `Win + R`, в появившемся окне введите `cmd` и пропишите команды:
```
git clone https://github.com/Lalka121/filecrypt
cd filecrypt
set PATH=%PATH%;.\bin
```

#### Unix:
```
git clone github.com/Lalka121/filecrypt
cd filecrypt
export PATH=$PATH:./bin
```

### Скачивание из GitHub
1. Скачайте репозиторий в виде архива
2. Разархивируйте репозиторий
3. Добавьте папку `./bin` в переменную `PATH`, например, как в предыдущем способе

## Использование (все команды следует прописывать после `filecrypt`)
Доступные команды:
- [help](#help)
- [generate-key](#generate-key)
- [encrypt](#encrypt)
- [decrypt](#decrypt)
- [list-key](#list-key)

#### help
Выводит справку со всем необходимым для работы программы    
```
$ filecrypt help
$ Шифровщик/Дешифровщик файлов
  Использование:
    generate-key [-m описание] <идентификатор>  Создать новый ключ
    encrypt <файл> <идентификатор>             Зашифровать файл
    decrypt <файл> <идентификатор>             Дешифровать файл
    list-key                                   Показать все ключи
```

#### generate-key
Генерирует новый ключ на основе кодировки base64
Аргументы:
1. *опционально*. Флаг `-m` добавляет описание ключу
2. Идентификатор ключа
```
$ filecrypt generate-key -m="new key" my-key
$ Успешно создан новый ключ с ID: my-key
```

#### encrypt
Хеширует файл на основе созданного ключа и создаёт новый файл `{path_to_file}.enc`
Аргументы:
1. Путь к файлу
2. Идентификатор ключа
```
$ filecrypt encrypt path_to_file my-key           
$ Файл успешно зашифрован
```

#### decrypt
Дехеширует зашифрованный файл с помощью ключа
Аргументы:
Аргументы:
1. Путь к файлу
2. Идентификатор ключа
```
$ filecrypt decrypt go.mod.enc my-key  
$ Файл успешно расшифрован
```

#### list-key
Выводит список созданных ключей, а также их описание
```
$ filecrypt list-key
$ Список ключей:
  - ID: k1
  - ID: my-key
    Описание: new key
```
