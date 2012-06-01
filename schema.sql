drop table if exists user;
create table user (
  user_id integer primary key autoincrement,
  username string not null,
  email string not null,
  pw_hash string not null
);

drop table if exists proposition;
create table proposition (
  proposition_id integer primary key autoincrement,
  created integer,
  author_id integer not null,
  text string not null,
  state integer not null
);

drop table if exists bet;
create table bet (
  bet_id integer primary key autoincrement,
  created integer,
  proposition_id integer not null,
  user_proposed integer not null,
  user_true integer not null,
  user_false integer not null,
  state integer not null
);
