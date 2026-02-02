-- 데이터베이스 생성
CREATE DATABASE IF NOT EXISTS web_backend
CHARACTER SET utf8mb4
COLLATE utf8mb4_general_ci;
USE web_backend;

-- users 테이블 생성
CREATE TABLE IF NOT EXISTS users (
    id CHAR(36) PRIMARY KEY, -- UUID를 저장할 CHAR(36) 형식
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL, -- 비밀번호는 해시된 값 저장
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- 가상머신 정보 저장 테이블
CREATE TABLE IF NOT EXISTS virtual_machines (
    vm_id CHAR(36) PRIMARY KEY, -- UUID 저장
    owner_id CHAR(36) NOT NULL, -- 소유자 (users 테이블과 연결)
    vm_name VARCHAR(100) NOT NULL,
    is_public BOOLEAN NOT NULL,
    instance_type INT NOT NULL,
    os INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 가상머신 공유 사용자 테이블 (Many-to-Many 관계)
CREATE TABLE IF NOT EXISTS vm_shared_users (
    id INT AUTO_INCREMENT KEY,
    vm_id CHAR(36) NOT NULL,
    user_id CHAR(36) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status ENUM('pending', 'accepted', 'rejected') DEFAULT 'pending',
    FOREIGN KEY (vm_id) REFERENCES virtual_machines(vm_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE verification_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    code VARCHAR(6) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (email)  -- 한 번에 하나의 인증 코드만 유지
);

-- 관리자 변경 요청 테이블
CREATE TABLE vm_admin_change_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    vm_id CHAR(36) NOT NULL,
    old_admin_id CHAR(36) NOT NULL,
    new_admin_id CHAR(36) NOT NULL,
    status ENUM('pending', 'verified', 'rejected') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vm_id) REFERENCES virtual_machines(vm_id) ON DELETE CASCADE,
    FOREIGN KEY (old_admin_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (new_admin_id) REFERENCES users(id) ON DELETE CASCADE
);



-- 인덱스 추가 (검색 성능 개선)
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_virtual_machines_owner ON virtual_machines(owner_id);
CREATE INDEX idx_vm_shared_users_vm ON vm_shared_users(vm_id);
CREATE INDEX idx_vm_shared_users_user ON vm_shared_users(user_id);
