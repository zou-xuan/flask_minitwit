drop table IF EXISTS user;

CREATE TABLE user(
  user_id integer PRIMARY KEY AUTOINCREMENT,
  username text NOT NULL,
  email text NOT NULL ,
  pw_hash text NOT NULL
);

DROP TABLE IF EXISTS follower;

CREATE TABLE follower(
  who_id integer,
  whom_id integer
);

DROP TABLE IF EXISTS message;

CREATE TABLE message(
  message_id integer PRIMARY KEY AUTOINCREMENT ,
  author_id integer NOT NULL ,
  text text NOT NULL ,
  pub_date integer
)