-- +goose Up
-- +goose StatementBegin
Create table if not exists UserAuth
(id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    userqn VARCHAR(100) UNIQUE,
    hpassword VARCHAR(100));

-- INSERT INTO userauth(userqn,hpassword)
-- values('admin@go-signal.com','admin') returning id;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS UserAuth;
-- +goose StatementEnd
