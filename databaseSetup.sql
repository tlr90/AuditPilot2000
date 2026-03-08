CREATE DATABASE IF NOT EXISTS azure_audit;
USE azure_audit;

CREATE TABLE IF NOT EXISTS status_types (
    id INT AUTO_INCREMENT NOT NULL,
    status_name VARCHAR(50),
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS resource_types (
    id INT AUTO_INCREMENT NOT NULL,
    type_name VARCHAR(80) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS security_findings (
    id INT AUTO_INCREMENT NOT NULL,
    resource_name VARCHAR(255) NOT NULL,
    type_id INT NOT NULL,
    status_id INT NOT NULL,
    ai_remidiation_text TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (type_id) REFERENCES resource_types(id),
    FOREIGN KEY (status_id) REFERENCES status_types(id)
);

INSERT INTO status_types (id, status_name) VALUES (1, "Insecure");
INSERT INTO resource_types (id, type_name) VALUES (1, "Storage Account"),(2,"Virtual Machine"),(3,"Users"),(4,"Azure KeyVault"),(5,"Virtual Networks");