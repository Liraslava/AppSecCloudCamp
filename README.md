# AppSecCloudCamp
Тестовое задание на стажировку AppSecCloudCamp

**1. Вопросы для разогрева**
- Расскажите, с какими задачами в направлении безопасной разработки вы сталкивались?
- Если вам приходилось проводить security code review или моделирование угроз, расскажите, как это было?
- Если у вас был опыт поиска уязвимостей, расскажите, как это было?
- Почему вы хотите участвовать в стажировке?

(так как в моём регионе невозможно создавать закрытые репозитории, данную информацию приложу в письме)

**2.1. Security code review**

Требуется провести анализ кода на GO с точки зрения безопасности и подготовить отчет по следующим пунктам:

- Какие уязвимости присутствуют в этом фрагменте кода? (Указать строки, в которых присутствуют уязвимости).
- К каким последствиям может привести эксплуатация найденных уязвимостей злоумышленником?
- Описать способы исправления уязвимостей (Если уязвимость можно исправить несколькими способами, необходимо перечислить их, выбрать лучший по вашему мнению и аргументировать свой выбор).

```
package main

import (
    "database/sql"
    "fmt"
    "log"
    "net/http"
    "github.com/go-sql-driver/mysql"
)

var db *sql.DB
var err error

func initDB() {
    db, err = sql.Open("mysql", "user:password@/dbname")
    if err != nil {
        log.Fatal(err)
    }

err = db.Ping()
if err != nil {
    log.Fatal(err)
    }
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" {
        http.Error(w, "Method is not supported.", http.StatusNotFound)
        return
    }

searchQuery := r.URL.Query().Get("query")
if searchQuery == "" {
    http.Error(w, "Query parameter is missing", http.StatusBadRequest)
    return
}

query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%'", searchQuery)
rows, err := db.Query(query)
if err != nil {
    http.Error(w, "Query failed", http.StatusInternalServerError)
    log.Println(err)
    return
}
defer rows.Close()

var products []string
for rows.Next() {
    var name string
    err := rows.Scan(&name)
    if err != nil {
        log.Fatal(err)
    }
    products = append(products, name)
}

fmt.Fprintf(w, "Found products: %v\n", products)
}

func main() {
    initDB()
    defer db.Close()

http.HandleFunc("/search", searchHandler)
fmt.Println("Server is running")
log.Fatal(http.ListenAndServe(":8080", nil))
}
```
В данном коде есть несколько потенциальных уязвимостей:

1. SQL Injection: запрос query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%'", searchQuery). В параметр "searchQuery" можно передать специально сформированную строку для выполнения SQL-запросов.
2. Отправка информации об ошмбках: в режиме production отправка всех интструкций об ошибках может привести к утечки конфиденциальной информации.

Методы решения:

1. Использовать параметризованные запросы вместо форматирования строки.
query := "SELECT * FROM products WHERE name LIKE ?"
2. Ограничить или скрыть информацию об ошибках.

(Использованная литература: [https://habr.com/ru/articles/308088/])

**2.2: Security code review: Python**

**2.2.1**
```
from flask import Flask, request
from jinja2 import Template

app = Flask(name)

@app.route("/page")
def page():
    name = request.values.get('name')
    age = request.values.get('age', 'unknown')
    output = Template('Hello ' + name + '! Your age is ' + age + '.').render()
return output

if name == "main":
    app.run(debug=True)
```
В данном коде есть несколько потенциальных уязвимостей:

1. SQL Injection: необработанный пользовательский ввод, в переменные "name" и "age" записываются знаечния, полученные из запроса пользователя без дополнительной проверки. 
2. XSS: неэкранированные значения в шаблоне Jinja2 (например, в перемнную "name" введётся скрипт, который выполнился как HTML на стороне клиента)
3. Уязвимость в `if name == "main"` - сравнения не произойдёт (п.1 - переменная n не определена).

Методы решения: 
1. Валидация переменных.
 ```
    if not name:
        return "Пожалуйста, введите имя"
     output = Template('Привет {name}! Твой возраст {age}).rendere(name=name, age=age)
     return output
    ```
2.  Исправить строки.
if __name__=="__main__"
app = Flask(__name__)

(Использованная литература: [https://www.codiga.io/blog/python-jinja2-autoescape/])

**2.2**

```from flask import Flask, request
import subprocess

app = Flask(name)

@app.route("/dns")
def dns_lookup():
    hostname = request.values.get('hostname')
    cmd = 'nslookup ' + hostname
    output = subprocess.check_output(cmd, shell=True, text=True)
return output
if name == "main":
    app.run(debug=True)
```

В данном коде есть несколько потенциальных уязвимостей:
1. Command Injection: переменная hostname используется напрямую в команде "nslookup", хотя она получена из запроса пользователа, следовательно, в неё можно предеать специально сформированную строку.
2. Уязвимость в `if name == "main"` - сравнения не произойдёт (п.1 - переменная n не определена).

Методы решения: 
1. Экранирование пользовательского ввода
2. Экранирование данных: можно использовать функцию "shlex.quote()".
3. Испльзование списка аргументов: вместо передачи строки в subprocess можно передaвать список аргументов. 

```python
from flask import Flask, request
import subprocess
import shlex

app = Flask(__name__)

@app.route("/dns")
def dns_lookup():
    hostname = request.values.get('hostname')

    if not re.match(r'^[a-zA-Z0-9.-]*$', hostname):
        return "Invalid hostname"

    cmd = ['nslookup', shlex.quote(hostname)]
    output = subprocess.check_output(cmd, text=True)
    
    return output

if __name__ == "__main__":
    app.run(debug=True)
```
(Использованная литература: [https://book.hacktricks.xyz/pentesting-web/command-injection])

**3. Моделирование угроз**
