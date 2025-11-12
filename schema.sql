
CREATE TABLE IF NOT EXISTS users (
    user_id INT PRIMARY KEY,
    user_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE,
    creation_date DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 插入一些初始数据 (用于测试)
-- INSERT IGNORE 会在 user_id 已存在时忽略错误
INSERT IGNORE INTO users (user_id, user_name, email, creation_date)
VALUES 
(101, 'Alice Smith', 'alice.smith@example.com', '2023-01-10 09:00:00'),
(102, 'Bob Johnson', 'bob.johnson@example.com', '2023-02-15 14:30:00'),
(103, 'Charlie Brown', 'charlie.brown@example.com', '2023-03-20 11:15:00');