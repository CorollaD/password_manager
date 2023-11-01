# password_manager
A password management tools

# dev help
# 打包成windows可执行文件
```
# step 1 安装依赖
pip install PySide6 cryptography pyinstaller -i  https://pypi.tuna.tsinghua.edu.cn/simple
# step 2 生成spec文件
pyinstaller --name password_manager --windowed --onefile main.py
# step 3
pyinstaller password_manager.spec
```
