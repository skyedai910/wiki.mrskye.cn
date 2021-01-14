# CTF密码学中python库应用
## Crypto

* 取 100 bit 长的随机质数

  ```python
  from Crypto.Util.number import getPrime
  getPrime(100)
  ```

* bytes 与 int 互换

  ```python
  from Crypto.Util.number import bytes_to_long, long_to_bytes
  bytes_to_long(b'this4bytes')
  long_to_bytes(123456789)
  ```

* 最大公约数

  ```python
  from Crypto.Util.number import GCD
  GCD(38,18)
  ```

* 是否为素数

  ```python
  from Crypto.Util.number import isPrime()
  isPrime(17)
  ```

## gmpy2

> gmpy2 安装比较麻烦，需要几个额外的运行环境，正常情况下 Ubuntu 没有。详情谷歌百度。

* 初始化一个大整数

  ```python
  from gmpy2 import mpz
  mpz(0x10)
  mpz(1234)
  ```

* 乘法逆元

  ```python
  from gmpy2 import invert
  d = invert(e,phi)
  ```

  