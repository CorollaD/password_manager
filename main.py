import sys
import logging
from PySide6.QtCore import QFile, QTextStream, Qt
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, \
    QMessageBox, QListWidget
from cryptography.fernet import Fernet

# 设置日志配置
logging.basicConfig(
    level=logging.INFO,
    filename='password_manager.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# 生成加密密钥
def generate_key():
    return Fernet.generate_key()


# 加载加密密钥
def load_key():
    with open("key.key", "rb") as key_file:
        return key_file.read()


# 保存加密密钥
def save_key(key):
    with open("key.key", "wb") as key_file:
        key_file.write(key)


# 加密密码
def encrypt_password(password, key):
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode())
    return encrypted_password


# 解密密码
def decrypt_password(encrypted_password, key):
    f = Fernet(key)
    decrypted_password = f.decrypt(encrypted_password)
    return decrypted_password.decode()


# 主窗口类
class PasswordManagerWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Password Manager")
        self.setFixedSize(400, 300)

        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout(self.central_widget)

        self.project_name_label = QLabel("Accounts Name:", self)
        self.layout.addWidget(self.project_name_label)

        self.project_name_edit = QLineEdit(self)
        self.layout.addWidget(self.project_name_edit)

        self.password_label = QLabel("Password:", self)
        self.layout.addWidget(self.password_label)

        self.password_edit = QLineEdit(self)
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password_edit)

        self.save_button = QPushButton("Save", self)
        self.save_button.clicked.connect(self.save_password)
        self.layout.addWidget(self.save_button)

        self.view_button = QPushButton("Accounts List", self)
        self.view_button.clicked.connect(self.view_passwords)
        self.layout.addWidget(self.view_button)

        self.passwords_list = QListWidget(self)
        self.passwords_list.itemDoubleClicked.connect(self.copy_password)
        self.layout.addWidget(self.passwords_list)

        self.key = None

        # 配置日志记录器
        self.logger = logging.getLogger('password_manager')

    # 加载密钥并创建加密器
    def load_key_and_create_fernet(self):
        try:
            self.key = load_key()
        except FileNotFoundError:
            self.key = generate_key()
            save_key(self.key)

    # 保存密码
    def save_password(self):
        self.load_key_and_create_fernet()
        project_name = self.project_name_edit.text()
        password = self.password_edit.text()

        if project_name and password:
            encrypted_password = encrypt_password(password, self.key)
            self.save_password_to_file(project_name, encrypted_password)
            self.logger.info(f"Saved password for project: {project_name}")
            QMessageBox.information(self, "Password Manager", "Password saved successfully.")
            self.project_name_edit.clear()
            self.password_edit.clear()
        else:
            QMessageBox.warning(self, "Password Manager", "Project name and password cannot be empty.")

    # 保存密码到文件
    def save_password_to_file(self, project_name, password):
        with open("passwords.txt", "a") as password_file:
            password_file.write(f"{project_name}:{password.decode()}\n")

    # 复制密码
    def copy_password(self):
        self.load_key_and_create_fernet()
        selected_item = self.passwords_list.currentItem()

        if selected_item:
            project_name = selected_item.text().split(":")[0].strip()
            encrypted_password = self.get_encrypted_password_from_file(project_name)

            if encrypted_password:
                decrypted_password = decrypt_password(encrypted_password, self.key)
                QApplication.clipboard().setText(decrypted_password)
                self.logger.info(f"Copied password for project: {project_name}")
                QMessageBox.information(self, "Password Manager", "Password copied to clipboard.")
            else:
                QMessageBox.warning(self, "Password Manager", "Project name not found.")

    # 从文件中获取加密密码
    def get_encrypted_password_from_file(self, project_name):
        with open("passwords.txt", "r") as password_file:
            for line in password_file:
                line = line.strip()
                if line.startswith(project_name + ":"):
                    encrypted_password = line.split(":", 1)[1]
                    return encrypted_password.encode()
        return None

    # 查看密码
    def view_passwords(self):
        self.passwords_list.clear()
        self.load_key_and_create_fernet()
        with open("passwords.txt", "r") as password_file:
            for line in password_file:
                project_name, encrypted_password = line.strip().split(":", 1)
                masked_password = "*" * 8  # 用星号表示密码
                self.passwords_list.addItem(f"{project_name}: {masked_password}")
        self.logger.info("Viewed passwords")

    # 删除账户与密码
    # 修改密码


# 应用程序入口点
if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = PasswordManagerWindow()
    window.show()

    sys.exit(app.exec())
