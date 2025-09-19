## usage

## bake
### 기본형 (대화형)
```
sudo ./syncLauperDongleMaker bake
```

### 비대화형, FAT32 + 읽기전용 속성 자동
```
  sudo ./syncLauperDongleMaker bake \
  --mode fat32 \
  --target /dev/sdb \
  --priv privkey.pem \
  --licensee "ACME Co." \
  --key-id k1 \
  --label SL-DONGLE \
  --readme ./README.pdf \
  --force
```

### 검증
```
./syncLauperDongleMaker verify --mount /media/dongle --pub pubkey.pem
```