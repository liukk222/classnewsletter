CREATE DATABASE IF NOT EXISTS classnewsletter;
USE classnewsletter;
CREATE TABLE `users` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  `deleted_at` datetime(3) DEFAULT NULL,
  `studentid` longtext,
  `class` longtext,
  `username` longtext,
  `password` longtext,
  `phonenumber` longtext,
  `qqnumber` longtext,
  `wxnumber` longtext,
  `address` longtext,
  PRIMARY KEY (`id`),
  KEY `idx_users_deleted_at` (`deleted_at`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci