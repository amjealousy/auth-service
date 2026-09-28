Create TABLE IF NOT EXISTS UserAuth
(id uuid DEFAULT gen_random_uuid() PRIMARY KEY NOT NULL,
 userqn VARCHAR(100) UNIQUE NOT NULL,
 hpassword VARCHAR(100) NOT NULL);

CREATE TABLE IF NOT EXISTS SESSIONS(
id uuid DEFAULT gen_random_uuid() PRIMARY KEY NOT NULL,
user_id uuid NOT NULL,
refresh_token varchar(512) NOT NULL,
is_revoked bool NOT NULL DEFAULT false,
created_at timestamp WITH TIME ZONE DEFAULT (now()),
expires_at timestamp WITH TIME ZONE DEFAULT (now()+ INTERVAL '2 hours'),
CONSTRAINT fk_userauth FOREIGN KEY (user_id) REFERENCES UserAuth(id)
);



