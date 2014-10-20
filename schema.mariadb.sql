--case class User(id: Int, login: String, password: String)
--case class Realm(id: Int, name: String)
--case class UserAttr(user: Int, name: String, value: String)
--case class Permission(id: Int, name: String)
--case class Profile(id: Int, realm: Int, name: String)
--case class ProfileMapping(user: Int, profile: Int)
--case class PermissionMapping(profile: Int, permission: Int)
--case class Session(user: Int, realm: Int, token: String, start: Timestamp, last: Timestamp, tag: String)

create table users (id int auto_increment  primary key not null, login varchar(32) unique not null, password varchar(128));
create table realm (name varchar(255) primary key not null);
create table extra_attrs (user_id int not null references users(id), name varchar(64) not null, `type` varchar(32), value text, primary key (user_id, name));
create table permission (id int auto_increment primary key not null, name varchar(128));
create table profile (id int auto_increment primary key not null, realm varchar(255) not null references realm(name), name varchar(64) unique not null);
create table user_profile (user_id int not null references users(id), profile_id int not null references profile(id), primary key (user_id, profile_id));
create table profile_permissions (profile int not null references profile(id), permission int not null references permission(id), primary key (profile, permission));
create table `session` (user_id int not null references users(id), realm varchar(255) not null references realm(name), token varchar(255) not null, start timestamp default current_timestamp, last timestamp default current_timestamp, tag varchar(255) not null, primary key (token, tag));
