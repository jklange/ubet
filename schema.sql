drop table if exists user;
create table user (
  user_id integer primary key autoincrement,
  username string not null,
  email string not null,
  pw_hash string not null
);

drop table if exists follower;
create table follower (
  who_id integer not null,
  whom_id integer not null
);

drop table if exists proposition;
create table proposition (
  proposition_id integer primary key autoincrement,
  author_id integer not null,
  global integer not null,
  text string not null,
  state integer not null
);

drop table if exists bet;
create table bet (
  bet_id integer primary key autoincrement,
  proposition_id integer not null,
  accepted integer not null,
  user_for integer not null,
  user_against integer not null,
  state integer not null
);

drop table if exists scoreboard;
create table scoreboard (
  user_one integer not null,
  user_two integer not null,
  user_one_bets_won not null,
  user_two_bets won not null,
  undecided_bets integer not null,
  disputed_bets integer not null
);
