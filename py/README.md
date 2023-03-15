# 一些脚本

## 创建数据表
使用目录下的create_student.sql创建数据表
```asm
$ mysql -uroot -p
## mysql中执行
> CREATE DATABASE test;
> USE test;
> SOURCE /path/to/create_student.sql;
```

## 生成随机数据
```asm
$ pip install -r requirements.insert.txt
$ python insert_mysql.py
```
修改password为数据库密码

修改num_inserts为指定生成数量

## 简单的透明代理
```asm
$ pip install -r requirements.proxy.txt
$ python trans_proxy.py
```
修改password为数据库密码
### 测试
```asm
## 测试连通，获取到“hello”证明连通
$ curl http://localhost:5432/hello
## 测试获取数据库数据
$ curl --data "sql=SELECT * FROM student limit 1" http://localhost:5432/admin/students
```