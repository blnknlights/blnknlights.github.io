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
```sql
.databases                    # display attached databases
.tables                       # display tables 
.schema users                 # show the schema of table users
.mode table                   # display as tables 
.headers on                   # display the column headers 
pragma table_info(user);
select * from key_names;
```

create and attach test.db
```sql
sqlite3 test.db 
```

attach an existing db
```sql
ATTACH DATABASE 'testDB.db' as 'TEST';
```

create a table schema
```sql
CREATE TABLE users(
   id INT PRIMARY KEY     NOT NULL,
   username       TEXT    NOT NULL,
   hash           TEXT    NOT NULL,
   salt           TEXT    NOT NULL
);
```

```
CREATE TABLE pies(
   ip           TEXT    NOT NULL,
   banner       TEXT,
   auth         TEXT,
   UNIQUE(ip)
);
```

```
INSERT INTO raspbian VALUES('asdf','asdf');
```

insert items in the table 
```sql
INSERT INTO users (id, username, hash, salt)
VALUES (1, 'Paul', '5f4dcc3b5aa765d61d8327deb882cf99', 'salty');
```

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

delete table
```sql
DROP TABLE table_name 
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
