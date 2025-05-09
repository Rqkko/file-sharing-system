# Setup Guide

1. Run the following command to install the required packages:
```bash
pip install pycryptodome
```

2. Generate keys
```bash
python secure_file_share.py --genkeys
```

3. Encrypt a file (That will expire in 60 seconds)
```bash
python secure_file_share.py --encrypt sample.txt --password mypass123 --expire 60
```

4. Decrypt a file
```bash
python secure_file_share.py --decrypt --password mypass123
```