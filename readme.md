# usage
syncLauper를 위한 키 동글 생성 프로그램

## IMPORTANT
- 라벨이 `SL-DONGLE` 일 경우, 리눅스에서 자동으로 `/media/dongle` 에 읽기 전용으로 마운트되도록 `/etc/fstab` 에 아래와 같이 작성한다
```
LABEL=SL-DONGLE  /media/dongle  auto  nofail,x-systemd.automount,x-systemd.idle-timeout=30,noatime,uid=1000,gid=1000,umask=022  0  0
```

## 키 생성
- privkey.pem, pubkey.pem을 생성합니다.
```
 syncLauperDongleMaker genkey
```

## 등글 제작 

### 대화형으로 제작
```
sudo ./syncLauperDongleMaker bake
```

### 비 대화형 제작, fat32
```
sudo ./syncLauperDongleMaker bake --mode fat32 --target /dev/sdb \
  --licensee "artcrew" --key-id k1 --label SL-DONGLE --force
```

### 재발급만 하는 경우 
```
sudo ./syncLauperDongleMaker bake --update-only --mount /media/dongle \
  --licensee "artcrew" --key-id k2 --priv privkey.pem
```

## 검증
```
./syncLauperDongleMaker verify --mount /media/dongle --pub pubkey.pem
```