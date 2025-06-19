---
title: "RSA"
date: 2025-06-19
---

# RSA 初级脚本合集

## 引言

RSA（Rivest-Shamir-Adleman）是一种非对称加密算法，广泛应用于数据加密和数字签名。它的安全性依赖于大整数分解的困难性。本讲义将深入探讨 RSA 的基本原理、常用工具以及如何根据其数学特性来分类和理解各种攻击方法。

---

## 一、RSA 基础回顾

### 1.1 基本原理

RSA 算法涉及三个主要步骤：**密钥生成**、**加密**和**解密**。

* **密钥生成：**
  1.  选择两个大素数 $p$ 和 $q$。
  2.  计算模数 $n = p \cdot q$。
  3.  计算欧拉函数 $\phi(n) = (p-1)(q-1)$。
  4.  选择一个整数 $e$ 作为公钥指数，满足 $1 < e < \phi(n)$ 且 $\gcd(e, \phi(n)) = 1$。
  5.  计算私钥指数 $d$，满足 $d \cdot e \equiv 1 \pmod{\phi(n)}$。
  6.  公钥为 $(n, e)$，私钥为 $(n, d)$。

* **加密：**
  明文 $M$ ($0 \le M < n$) 通过公钥 $(n, e)$ 加密为密文 $C$：
  $$C \equiv M^e \pmod{n}$$

* **解密：**
  密文 $C$ 通过私钥 $(n, d)$ 解密为明文 $M$：
  $$M \equiv C^d \pmod{n}$$

---

## 二、常用工具

### 2.1 大素数分解工具

RSA 的安全性依赖于分解大整数 $n$ 为其素因子 $p$ 和 $q$ 的困难性。以下是一些常用的大素数分解工具和方法：

* **Factordb：** 一个在线整数因子分解数据库。网址：`http://www.factordb.com/`，API：`http://factordb.com/api?query=`
* **Yafu：** 一款功能强大的命令行因子分解工具，对 $p, q$ 相差过大或过小的情况表现良好。
* **SageMath：** 一个开源的数学软件系统，内置了 `divisors(n)` 等函数用于小素数分解。在线环境：`https://sagecell.sagemath.org/`
* **Pollard’s** $p-1$ **方法：** 适用于分解具有小素因子 $p-1$ 的合数 (光滑数)。例如：`python -m primefac -vs -m=p-1 xxxxxxx`
* **Williams’s** $p+1$ **方法：** 适用于分解具有小素因子 $p+1$ 的合数 (光滑数)。例如：`python -m primefac -vs -m=p+1 xxxxxxx`
* **CADO-NFS：** 最先进的通用数字域筛法实现，适用于分解非常大的整数。

### 2.2 OpenSSL 工具

OpenSSL 是一个强大的密码学工具包，可用于 RSA 密钥的解析和操作。

* **解析加密密钥：**

  ```bash
  openssl rsa -pubin -text -modulus -in pub.key
  ```

* **生成解密密钥并解密：**
  如果已知私钥参数（例如 $p, q, e$），你可以使用工具生成私钥文件，然后进行解密。

  ```bash
  python rsatool.py -f PEM -o key.key -p 1 -q 1 -e 1
  openssl rsautl -decrypt -inkey key.pem -in flag.enc -out flag
  # OAEP填充方式
  openssl rsautl -decrypt -oaep -inkey key.pem -in flag.enc -out flag
  ```

### 2.3 脚本生成解密密钥

以下 Python 脚本可用于根据 RSA 组件构建私钥并导出为 PEM 格式：

```python
from Cryptodome.PublicKey import RSA

# 假设你已经获得了 n, e, d, p, q 的值
n = 0 
e = 0
d = 0
p = 0 
q = 0 

# 构建RSA密钥对
rsa_components = (n, e, d, p, q)
myrsa = RSA.construct(rsa_components)

# 将私钥导出为PEM格式
private_key_file = open('private.pem', 'w')
private_key_file.write(myrsa.export_key().decode('utf-8'))
private_key_file.close()
```

### 2.4 常用脚本集

这里是一些 GitHub 上常用的 RSA 攻击脚本集合：

* **RsaCtfTool：** `https://github.com/Ganapati/RsaCtfTool`

  * 用法示例：

    * 已知公钥自动求私钥并解密：

      ```bash
      python3 RsaCtfTool.py --publickey 公钥文件 --uncipherfile 加密文件
      ```

    * 已知公钥求私钥：

      ```bash
      python3 RsaCtfTool.py --publickey 公钥文件 --private
      ```

    * 密钥格式转换（PEM 转 $n, e$）：

      ```bash
      python3 RsaCtfTool.py --dumpkey --key 公钥文件
      ```

    * 密钥格式转换（$n, e$ 转 PEM）：

      ```bash
      python3 RsaCtfTool.py --createpub -n 782837482376192871287312987398172312837182 -e 65537
      ```

* **RSA-In-CTF：** `https://github.com/yifeng-lee/RSA-In-CTF`

* **CTF-Crypto：** `https://github.com/ValarDragon/CTF-Crypto`

---

## 三、典型攻击场景：按数学类型分类

本节将根据其利用的数学原理，详细分类和介绍针对 RSA 的各种攻击方法。

### 3.1 基础数论计算

这类攻击主要利用 RSA 算法在密钥参数完全已知或可直接推导的情况下，进行基本的数论计算来解密。

#### 3.1.1 已知 $p, q, e, c$

如果你知道所有生成密钥的参数和密文，你可以直接计算私钥 $d$ 并解密。

* **原理：**
  1.  计算模数 $n = p \cdot q$。
  2.  计算欧拉函数 $\phi(n) = (p-1)(q-1)$。
  3.  利用扩展欧几里得算法计算私钥指数 $d \equiv e^{-1} \pmod{\phi(n)}$。
  4.  通过 $M \equiv C^d \pmod{n}$ 解密明文 $M$。

* **Python 脚本：**

```python
import gmpy2 as gp
import binascii

p = 0 
q = 0 
e = 0 
c = 0 

n = p * q
phi = (p - 1) * (q - 1)
d = gp.invert(e, phi)
m = gp.powmod(c, d, n)

print(m)
print(binascii.unhexlify(hex(m)[2:]))
```

#### 3.1.2 已知 $n, e, d_p, c$

当你知道 $d_p = d \pmod{p-1}$ 时，可以通过 $d_p$ 来推导 $p$ 和 $q$。

* **原理：**
  我们知道 $e \cdot d \equiv 1 \pmod{\phi(n)}$，所以 $e \cdot d_p \equiv 1 \pmod{p-1}$。
  这意味着 $e \cdot d_p - 1 = k' (p-1)$。因此 $p = \frac{e \cdot d_p - 1}{k'} + 1$。
  由于 $d_p < p-1$，我们可以推断 $k'$ 的范围通常较小。我们可以遍历 $k'$ 的可能值来找到正确的 $p$。

* **Python 脚本：**

```python
import gmpy2 as gp

e = 0 
n = 0 
dp = 0 
c = 0 

# 遍历 k'
for k_prime in range(1, e):
    if (e * dp - 1) % k_prime == 0:
        p = (e * dp - 1) // k_prime + 1
        if n % p == 0:
            q = n // p
            phi_n = (p - 1) * (q - 1)
            d = gp.invert(e, phi_n)
            m = gp.powmod(c, d, n)
            if len(hex(m)[2:]) % 2 == 1:
                continue
            print('-------------------')
            print(f"明文整数: {m}")
            print(f"明文十六进制: {hex(m)[2:]}")
            print(f"明文字节串: {bytes.fromhex(hex(m)[2:])}")
            break
```

#### 3.1.3 已知 $p, q, d_p, d_q, c$

已知 CRT 指数 $d_p = d \pmod{p-1}$ 和 $d_q = d \pmod{q-1}$。你可以利用**中国剩余定理 (CRT)** 来重构 $d$。

* **原理：**
  我们有 $d \equiv d_p \pmod{p-1}$ 和 $d \equiv d_q \pmod{q-1}$。这是一个典型的中国剩余定理问题，可以直接求解 $d$。

* **Python 脚本：**

```python
import gmpy2 as gp
import binascii

p = 0 
q = 0 
dp = 0 
dq = 0 
c = 0 

n = p * q
phi_n = (p - 1) * (q - 1)

# 利用 CRT 性质重构 d
common_divisor = gp.gcd(p - 1, q - 1)
d = (dp - dq) // common_divisor * gp.invert((q - 1) // common_divisor, (p - 1) // common_divisor) * (q - 1) + dq

print(f"私钥d: {d}")
m = gp.powmod(c, d, n)
print('-------------------')
print(f"明文整数: {m}")
print(f"明文十六进制: {hex(m)[2:]}")
print(f"明文字节串: {bytes.fromhex(hex(m)[2:])}")
```

#### 3.1.4 已知 $e, d, n$

如果你知道 $e, d, n$，你可以分解 $n$ 得到 $p$ 和 $q$。

* **原理：**
  我们知道 $e \cdot d - 1 = k \cdot \phi(n)$。利用这一关系，以及 $\phi(n) = (p-1)(q-1)$，可以通过概率算法分解 $n$。核心是利用费马小定理的逆向应用。

* **Python 脚本1：** (基于 $k = e \cdot d - 1$)

```python
import random
import gmpy2

def divide_pq(e_val, d_val, n_val):
    k_val = e_val * d_val - 1
    while True:
        g = random.randint(2, n_val - 1)
        t = k_val
        while True: 
            if t % 2 != 0:
                break
            t //= 2
        
        x = pow(g, t, n_val)
        if x > 1 and gmpy2.gcd(x - 1, n_val) > 1:
            p = gmpy2.gcd(x - 1, n_val)
            return (p, n_val // p)

e = 0 
d = 0 
n = 0 

p, q = divide_pq(e, d, n)
print(f"p = {p}")
print(f"q = {q}")
```

* **Python 脚本2：** (基于 $\phi(n)$ 的分解)

```python
import random
import gmpy2

def factor_with_kphi(n_val, kphi_val):
    t = 0
    temp_kphi = kphi_val
    while temp_kphi % 2 == 0:
        temp_kphi >>= 1
        t += 1
    
    for i in range(1, 101): 
        g = random.randint(2, n_val - 1) 
        
        y = pow(g, temp_kphi, n_val)
        if y == 1 or y == n_val - 1:
            continue
        else:
            for j in range(1, t):
                x = pow(y, 2, n_val)
                if x == 1:
                    p = gmpy2.gcd(n_val, y - 1)
                    q = n_val // p
                    if p != 1 and p != n_val: 
                        return p, q
                elif x == n_val - 1:
                    break 
                y = x
            
            if y != 1 and y != n_val - 1:
                p = gmpy2.gcd(n_val, y - 1)
                q = n_val // p
                if p != 1 and p != n_val:
                    return p, q

    return None, None 

n = 0
e = 0
d = 0

k_phi = e * d - 1 

p_val, q_val = factor_with_kphi(n, k_phi)
if p_val and q_val:
    print(f"p = {p_val}")
    print(f"q = {q_val}")
else:
    print("未能成功分解 n。")
```

#### 3.1.5 Rabin 加密

Rabin 加密是一种基于模平方根的公钥加密方案，其加密指数 $e=2$。

* **原理：**
  加密：$C \equiv M^2 \pmod{n}$。
  解密需要计算 $C$ 的模 $n$ 平方根。这通常涉及中国剩余定理和计算模素数的平方根。由于一个数在模合数 $n$ 下可能有四个平方根，Rabin 解密通常会返回四个可能的明文。

* **Python 脚本：**

```python
import gmpy2
import binascii
from Cryptodome.Util.number import *

def rabin_decrypt(c_val, p_val, q_val, e_val=2):
    n_val = p_val * q_val
    
    mp = pow(c_val, (p_val + 1) // 4, p_val)
    mq = pow(c_val, (q_val + 1) // 4, q_val)
    
    yp = gmpy2.invert(p_val, q_val)
    yq = gmpy2.invert(q_val, p_val)
    
    r1 = (yp * p_val * mq + yq * q_val * mp) % n_val
    r2 = n_val - r1
    r3 = (yp * p_val * mq - yq * q_val * mp) % n_val
    r4 = n_val - r3
    
    return (r1, r2, r3, r4)

c = 0 
p = 0 
q = 0 

m_candidates = rabin_decrypt(c, p, q)

for i, m_val in enumerate(m_candidates):
    try:
        hex_m = hex(m_val)[2:]
        if len(hex_m) % 2 != 0: 
            hex_m = '0' + hex_m
        
        decoded_m = binascii.unhexlify(hex_m)
        print(f"候选明文 {i+1}: {decoded_m}")
    except binascii.Error as e_inner:
        print(f"候选明文 {i+1} 解码失败: {e_inner}")
    except Exception as e_inner:
        print(f"处理候选明文 {i+1} 时发生错误: {e_inner}")
```

---

### 3.2 基于连分数理论的攻击

这类攻击利用**连分数 (Continued Fractions)** 的性质，通过对某个比值进行连分数展开，来逼近一个有理数，从而发现 RSA 密钥的弱点。

#### 3.2.1 低解密指数攻击 / 低私钥指数攻击 (Wiener Attack)

当私钥指数 $d$ 过小（通常 $d < N^{0.25}$）时，RSA 可能容易受到 Wiener 攻击。

* **原理：**
  Wiener 攻击基于 $e \cdot d - 1 = k \cdot \phi(n)$ 且 $\phi(n) \approx n$。这表明 $\frac{e}{n} \approx \frac{k}{d}$。通过对 $\frac{e}{n}$ 进行连分数展开，其渐进分数 $\frac{k_i}{d_i}$ 中可能包含正确的 $\frac{k}{d}$。

* **Python 脚本1 (SageMath 环境)：**

```python
# Sage
from sage.all import *

def factor_rsa_wiener(N_val, e_val):
    N_val = Integer(N_val)
    e_val = Integer(e_val)
    
    cf = (e_val / N_val).continued_fraction().convergents()
    
    for f in cf:
        k = f.numer()
        d = f.denom()
        
        if k == 0:
            continue
        
        if (e_val * d - 1) % k != 0:
            continue
        phi_N = (e_val * d - 1) // k
        
        b = -(N_val - phi_N + 1)
        discriminant = b**2 - 4 * N_val
        
        if discriminant.sign() == 1: 
            sqrt_discriminant = sqrt(discriminant)
            if sqrt_discriminant.is_integer(): 
                p_candidate = (-b + sqrt_discriminant) // 2
                q_candidate = (-b - sqrt_discriminant) // 2
                
                if p_candidate.is_integer() and q_candidate.is_integer() and (p_candidate * q_candidate) == N_val:
                    if p_candidate < 0 or q_candidate < 0:
                        continue
                    
                    if p_candidate > q_candidate:
                        return (p_candidate, q_candidate)
                    else:
                        return (q_candidate, p_candidate)
    return None 

N = Integer(0)
e = Integer(0)
c = Integer(0)

p, q = factor_rsa_wiener(N, e)
if p and q:
    phi = (p - 1) * (q - 1)
    d = inverse_mod(e, phi)
    m = pow(c, d, N)
    print(f"找到 p: {p}")
    print(f"找到 q: {q}")
    print(f"明文: {bytes.fromhex(hex(m)[2:])}")
else:
    print("Wiener 攻击失败。")
```

* **Python 脚本2：** (通用 Python 环境，需要 `gmpy2`)

```python
import gmpy2
import binascii

def rational_to_contfrac(x, y):
    a = x // y
    pquotients = [a]
    while a * y != x:
        x, y = y, x - a * y
        a = x // y
        pquotients.append(a)
    return pquotients

def convergents_from_contfrac(frac_list):
    convs = []
    for i in range(len(frac_list)):
        convs.append(contfrac_to_rational(frac_list[0 : i + 1]))
    return convs

def contfrac_to_rational(frac_list):
    if not frac_list:
        return (0, 1)
    num = frac_list[-1]
    denom = 1
    for _ in range(len(frac_list) - 2, -1, -1):
        num, denom = frac_list[_] * num + denom, num
    return (num, denom)

def isqrt(n_val):
    x = n_val
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n_val // x) // 2
    return y 

def crack_rsa_wiener(e_val, n_val):
    frac = rational_to_contfrac(e_val, n_val)
    convergents = convergents_from_contfrac(frac)
    
    for (k, d) in convergents:
        if k != 0 and (e_val * d - 1) % k == 0:
            phi = (e_val * d - 1) // k
            s = n_val - phi + 1
            D = s * s - 4 * n_val
            if D >= 0:
                sq = isqrt(D)
                if sq * sq == D and (s + sq) % 2 == 0:
                    return d 

    return None

n = 0 
e = 0 
c = 0 

d = crack_rsa_wiener(e, n)
if d:
    m = pow(c, d, n)
    print(binascii.unhexlify(hex(m)[2:]))
else:
    print("Wiener 攻击失败，未找到 d。")
```

* **Python 脚本3：** (更简洁的 Wiener 攻击脚本)

```python
from Cryptodome.Util.number import long_to_bytes
import gmpy2

def transform(x, y):
    arr = []
    while y:
        arr += [x // y]
        x, y = y, x % y
    return arr 

def sub_fraction(k_list):
    x = 0
    y = 1
    for i in k_list[::-1]:
        x, y = y, x + i * y
    return (y, x) 

e = 0 
n = 0 
c = 0 

data = transform(e, n) 
for x_idx in range(1, len(data) + 1):
    data1 = data[:x_idx] 
    k_val, d_val = sub_fraction(data1)
    
    if k_val == 0: 
        continue
    
    if (e * d_val - 1) % k_val == 0:
        phi_n_candidate = (e * d_val - 1) // k_val
        
        s = n - phi_n_candidate + 1
        delta = s**2 - 4 * n
        if delta >= 0 and gmpy2.is_square(delta):
            sqrt_delta = gmpy2.isqrt(delta)
            p_candidate = (s + sqrt_delta) // 2
            q_candidate = (s - sqrt_delta) // 2
            
            if p_candidate * q_candidate == n and p_candidate != 1 and q_candidate != 1:
                m = pow(c, d_val, n)
                try:
                    flag_bytes = long_to_bytes(m)
                    if b'flag{' in flag_bytes:
                        print(flag_bytes)
                        break
                except Exception as e_inner:
                    print(f"解码失败: {e_inner}")
```

#### 3.2.2 变种1：$N_1N_2 < q_1q_2 < 1$

当存在两个模数 $N_1, N_2$ 且满足特定条件，例如 $N_1 = p_1 q_1$ 和 $N_2 = p_2 q_2$，其中 $q_1, q_2$ 之间存在某种关系时，可以通过连分数逼近 $N_1/N_2$ 来找到相关的素因子。

* **原理：**
  如果 $q_1/q_2$ 可以被 $N_1/N_2$ 的连分数渐进分数很好地逼近，那么你可以将 $N_1/N_2$ 展开为连分数，并检查其渐进分数 $(t_i, s_i)$。如果 $N_1$ 能被 $t_k$ 整除，那么 $q_1 = t_k$ 且 $q_2 = s_k$。

* **Python 脚本：**

```python
import gmpy2

def transform(x, y): 
    res = []
    while y:
        res.append(x // y)
        x, y = y, x % y
    return res 

def continued_fraction(sub_res): 
    numerator, denominator = 1, 0
    for i in sub_res[::-1]:
        denominator, numerator = numerator, i * numerator + denominator
    return denominator, numerator 

def sub_fraction(x, y):
    res_list = transform(x, y)
    fractions = []
    for i in range(1, len(res_list) + 1):
        fractions.append(continued_fraction(res_list[0:i]))
    return fractions

def wienerAttack_variant1(n1, n2):
    for (q2_candidate, q1_candidate) in sub_fraction(n1, n2):
        if q1_candidate == 0: 
            continue
        if n1 % q1_candidate == 0 and q1_candidate != 1:
            return (q1_candidate, q2_candidate)
    print("该方法不适用")
    return None

N1 = 0
N2 = 0

result = wienerAttack_variant1(N1, N2)
if result:
    q1_found, q2_found = result
    print(f"找到 q1: {q1_found}")
    print(f"找到 q2: {q2_found}")
else:
    print("未找到合适的 q1, q2。")
```

#### 3.2.3 变种2：$Ax \equiv y \pmod{P}$

这种形式的同余方程可以利用 Wiener 攻击或格攻击来解决。

* **Wiener's 方法：** 将方程转换为 $\left|\frac{A}{P} - \frac{k}{x}\right| \le \frac{1}{2x^2}$ 的形式，然后使用连分数逼近 $\frac{A}{P}$ 来找到 $\frac{k}{x}$。
* **Lattice 方法：** 构造一个格矩阵 $M = \begin{pmatrix} 1 & 0 \\ A & P \end{pmatrix}$，向量 $(x, k)$ 乘以 $M$ 得到 $(x, Ax + kP)$，如果 $y = Ax + kP$ 较小，则 $(x, y)$ 可能是格中的一个短向量，可以使用 LLL 算法求出。

#### 3.2.4 变种3：$N=p^2q$, $q<p<2q$, $d=N^\beta$

当模数形式为 $N=p^2q$ 且私钥指数 $d$ 较小并满足特定边界条件时，可以利用对 $e/N^{2/3}$ 或 $e/(N^{2/3}-N^{1/3})$ 的连分数逼近来尝试分解。

---

### 3.3 基于格理论 (Lattice Theory) 的攻击

格理论在密码学攻击中扮演着重要角色，尤其是在处理关于小根或近似根的问题时。LLL (Lenstra–Lenstra–Lovász) 算法是格约化中最常用的算法。

#### 3.3.1 Boneh and Durfee 攻击

Boneh and Durfee 攻击是 Wiener 攻击的推广，它在加密指数 $e$ 非常大（接近 $N$）且私钥指数 $d$ 较小（通常 $d < N^{0.292}$）时适用。

* **原理：**
  该攻击通过构造一个关于 $d$ 和另一个变量（通常是 $k$）的多项式，并在模 $e$ 下找到其小根。核心思想是利用 $ed - k\phi(N) = 1$ 这个关系，并将 $\phi(N)$ 近似为 $N - p - q + 1$。通过构建一个合适的格，利用 LLL 算法找到多项式的小根，从而恢复 $d$。

#### 3.3.2 变种1：已知 $n, e, d_p0, c, k$，其中 $d_p0$ 为 $d_p$ 的高位

如果 $d_p$ 的高位已知，可以利用 **Coppersmith 攻击**。

* **原理：**
  我们知道 $e \cdot d_p \equiv 1 \pmod{p-1}$。设 $d_p = (d_{p0} << k) + x$，其中 $x$ 是 $d_p$ 未知的低 $k$ 位。代入方程得到 $e \cdot ((d_{p0} << k) + x) - 1 \equiv 0 \pmod{p-1}$。这可以构造一个关于 $x$ 的多项式，并通过格方法寻找小根。

* **Sage 脚本 (Coppersmith 攻击)：**

```python
# Sage
from sage.all import *

dp0 = Integer(0) 
e = Integer(0)
n = Integer(0)

F = PolynomialRing(Zmod(n), 'x')

for k_prime_val in range(1, e):
    f = e * (dp0 * (1 << 200) + F.gen()) + k_prime_val - 1
    
    roots = f.small_roots(X=2**(200 + 1), beta=0.44, epsilon=Integer(1)/32)

    if len(roots) != 0:
        dp = roots[0] + (dp0 * (1 << 200))
        for k_val in range(2, e): 
            p = (e * Integer(dp) - 1 + k_val) // k_val
            if n % p == 0:
                break
        
        if p > 0: 
            print(f"k_prime = {k_prime_val}")
            print(f"p = {p}")
            print(f"dp = {dp}")
            break
```

#### 3.3.3 变种4：已知 $N, e, c$，其中 $d_p$ 过小

这种情况通常需要更高级的格攻击，如 Boneh and Durfee 攻击的变体。

* **原理：**
  当 $d_p$ 过小时，RSA 可能变得不安全。攻击的目标是找到一个 $p$ 或 $q$ 的小因子。Coppersmith 定理的推广可以解决这类问题，通常需要构建一个特定的格来找到方程的小根。

* **情形1：$q < N^{0.382}$**
  这种情况下，可以通过构造特殊的格并使用 LLL 算法来找到 $p$ 或 $q$。通常涉及到定义参数 $\beta = \frac{\text{qbit}}{\text{Nbit}}$ 和 $\delta = \frac{\text{dpbit}}{\text{Nbit}}$。

  * **Sage 脚本1：** (通用 Boneh and Durfee 变体)

```python
# Sage
from sage.all import *

def C(a, b):
    ret = 1
    for i in range(b):
        ret = ret * (a - i) // (i + 1)
    return ret

def get_matrix(scale, m_value, N_val, E_val, delta_val, beta_val):
    M = [[0 for _ in range(scale)] for _ in range(scale)]
    
    X_val = int(pow(N_val, delta_val) * pow(2, (scale + 1) // 2))
    Y_val = int(pow(N_val, delta_val + beta_val) * pow(2, (scale + 1) // 2))

    for i in range(scale):
        for j in range(scale):
            M[i][j] = (N_val**(max(m_value - i, 0))) * \
                      (E_val**(max(i - j, 0))) * \
                      (X_val**(scale - 1 - j)) * \
                      (Y_val**j) * \
                      C(i, j) * \
                      (pow(-1, j))
    return M

N = Integer(0)
E = Integer(0)
delta = 0.01 
beta = 0.37 
Scale = 35    
Mvalue = 22   

M_matrix = get_matrix(Scale, Mvalue, N, E, delta, beta)
M_matrix_sage = matrix(ZZ, M_matrix)
A = M_matrix_sage.LLL()[0] 

p_coeffs = []
X_val = int(pow(N, delta) * pow(2, (Scale + 1) // 2))
Y_val = int(pow(N, delta + beta) * pow(2, (Scale + 1) // 2))

for i in range(Scale):
    p_coeffs.append(A[i] // (X_val**(Scale - 1 - i) * Y_val**i))

PR = PolynomialRing(ZZ, 'x, y')
f = 0
for i in range(Scale):
    f += p_coeffs[i] * PR.gen(0)**(Scale - 1 - i) * PR.gen(1)**i

print(f.factor())
```

    * **Sage 脚本2：** (另一种格构造方法)

```python
# Sage
from sage.all import *

n_val = Integer(0)
e_val = Integer(0)

n_poly_deg = 12 
beta_val = 0.36 
delta_val = 0.02 

X_upper_bound = int(n_val * delta_val**(n_poly_deg + 1) / 2)
Y_upper_bound = int(n_val * (delta_val + beta_val)**(n_poly_deg + 1) / 2)

def C(a, b):
    ret = 1
    for i in range(b):
        ret = ret * (a - i) // (i + 1)
    return ret

def get_matrix_lll(n_dim, m_val):
    MM = [[0 for _ in range(n_dim)] for _ in range(n_dim)]
    for j in range(n_dim):
        p_N_power = max(0, m_val - j)
        for i in range(j + 1):
            MM[j][i] = (n_val**p_N_power) * \
                       (X_upper_bound**(n_dim - i - 1)) * \
                       (Y_upper_bound**i) * \
                       (e_val**(j - i)) * \
                       C(j, i) * \
                       (pow(-1, i))
    return MM

M_matrix_lll = get_matrix_lll(n_poly_deg, n_poly_deg // 2 + 1)
L = matrix(ZZ, M_matrix_lll).LLL()[0] 

x, y = var('x'), var('y')
f_poly = 0
for i in range(n_poly_deg):
    f_poly += (x**(n_poly_deg - i - 1)) * \
              (y**i) * \
              (L[i] // (X_upper_bound**(n_poly_deg - i - 1)) // (Y_upper_bound**i))

print(f_poly.factor())
```

* **情形2：$q < N^{0.468}$**
  这通常是 Boneh and Durfee 攻击的直接应用场景。

  * **原理：**
    Boneh and Durfee 攻击解决了当 $d < N^{0.292}$ 时的 RSA 漏洞。它通过构造一个二维多项式 $f(x, y) = 1 + x(N - y) - e \cdot d'$，其中 $x, y$ 对应 $k, p$，并在模 $e$ 下找到其小根。

  * **Sage 脚本：**

```python
# Sage
from sage.all import *
from copy import deepcopy

N = Integer(0)
e = Integer(0)
alpha = log(e, N) 
beta = 0.292      
delta = 0.292     

P = PolynomialRing(ZZ, 'x,y,z')

X_val = ceil(2 * N^(alpha + beta + delta - 1))
Y_val = ceil(2 * N^beta)
Z_val = ceil(2 * N^(1 - beta))

def f(x, y):
    return x * (N - y) + N

def trans(poly):
    my_tuples = poly.exponents(as_ETuples=False)
    g = 0
    for my_tuple in my_tuples:
        exponent = list(my_tuple)
        mon = P.gen(0)**exponent[0] * P.gen(1)**exponent[1] * P.gen(2)**exponent[2]
        tmp = poly.monomial_coefficient(mon)
        
        my_minus = min(exponent[1], exponent[2])
        exponent[1] -= my_minus
        exponent[2] -= my_minus
        tmp *= N**my_minus
        tmp *= P.gen(0)**exponent[0] * P.gen(1)**exponent[1] * P.gen(2)**exponent[2]
        
        g += tmp
    return g

m_value = 5 
tau = ((1 - beta)**2 - delta) / (2 * beta * (1 - beta))
sigma = (1 - beta - delta) / (2 * (1 - beta))

s_val = ceil(sigma * m_value)
t_val = ceil(tau * m_value)

my_polynomials = []

for i in range(m_value + 1):
    for j in range(m_value - i + 1):
        g_ij = trans(e**(m_value - i) * P.gen(0)**j * P.gen(2)**s_val * f(P.gen(0), P.gen(1))**i)
        my_polynomials.append(g_ij)

for i in range(m_value + 1):
    for j in range(1, t_val + 1):
        h_ij = trans(e**(m_value - i) * P.gen(1)**j * P.gen(2)**s_val * f(P.gen(0), P.gen(1))**i)
        my_polynomials.append(h_ij)

known_set = set()
new_polynomials = []
my_monomials = []

while len(my_polynomials) > 0:
    found_poly = False
    for i in range(len(my_polynomials)):
        f_current = my_polynomials[i]
        current_monomial_set = set(P.gen(0)**tx * P.gen(1)**ty * P.gen(2)**tz for tx, ty, tz in f_current.exponents(as_ETuples=False))
        delta_set = current_monomial_set - known_set
        
        if len(delta_set) == 1:
            new_monomial = list(delta_set)[0]
            my_monomials.append(new_monomial)
            known_set |= current_monomial_set
            new_polynomials.append(f_current)
            my_polynomials.pop(i)
            found_poly = True
            break
    if not found_poly:
        raise Exception('未找到符合条件的多项式，请检查参数设置或攻击条件。')

my_polynomials = deepcopy(new_polynomials)
nrows = len(my_polynomials)
ncols = len(my_monomials)

L = [[0 for _ in range(ncols)] for _ in range(nrows)]

for i in range(nrows):
    g_scale = my_polynomials[i]
    for j in range(ncols):
        L[i][j] = g_scale.monomial_coefficient(my_monomials[j])
        
        N_Power = 1
        current_coeff = L[i][j]
        while current_coeff % N == 0 and current_coeff != 0:
            N_Power *= N
            current_coeff //= N
        
        L[i][j] = current_coeff
        if j != i: 
             L[i][j] = (L[i][j] * inverse_mod(N_Power, e**m_value)) % (e**m_value)

L_matrix = matrix(ZZ, L)
L_matrix_LLL = L_matrix.LLL() 

reduced_polynomials = []
for i in range(nrows):
    g_l = 0
    for j in range(ncols):
        g_l += L_matrix_LLL[i][j] * my_monomials[j]
    reduced_polynomials.append(g_l)

my_ideal_list = [P.gen(1) * P.gen(2) - N] + reduced_polynomials
my_ideal_list = [H.change_ring(QQ) for H in my_ideal_list] 

for i in range(len(my_ideal_list), 3, -1): 
    print(f"尝试理想维度: {i}")
    V = Ideal(my_ideal_list[:i]).variety(ring=ZZ)
    if V:
        print(f"找到根: {V}")
        break 
```

#### 3.3.4 Coppersmith 攻击（已知 $p$ 的高位攻击）

如果已知素因子 $p$ 的部分高位，你可以通过 Coppersmith 攻击找到完整的 $p$。

* **原理：**
  设 $p = p_{high} + x$，其中 $p_{high}$ 是已知的高位， $x$ 是未知的小尾数。我们知道 $p$ 是 $N$ 的一个因子，所以 $N \equiv 0 \pmod{p}$。构造多项式 $f(x) = p_{high} + x \pmod{N}$。由于 $f(x) \equiv 0 \pmod{p}$，且 $x$ 是小根，可以利用 Coppersmith 定理在模 $N$ 下找到 $x$。

* **Sage 脚本：**

```python
# Sage
from sage.all import *

n = Integer(0)
p4 = Integer(0) 

pbits = n.nbits() // 2 
kbits = pbits - p4.nbits() 
print(f"p4 的比特数: {p4.nbits()}")

p4 = p4 << kbits

PR = PolynomialRing(Zmod(n), 'x')
f = PR.gen() + p4 

roots = f.small_roots(X=2**kbits, beta=0.4) 

if roots:
    p = p4 + int(roots[0])
    if n % p == 0:
        q = n // p
        print(f"n: {n}")
        print(f"找到 p: {p}")
        print(f"找到 q: {q}")
    else:
        print("找到的根不是 n 的因子。")
else:
    print("未找到小根，Coppersmith 攻击失败。")
```

#### 3.3.5 Coppersmith 攻击（已知 $m$ 的高位攻击）

如果已知明文 $M$ 的部分高位，你可以通过 Coppersmith 攻击恢复完整的 $M$。

* **原理：**
  设 $M = m_{high} + x$，其中 $m_{high}$ 是已知的高位， $x$ 是未知的小尾数。加密过程为 $C \equiv (m_{high} + x)^e \pmod{N}$。构造多项式 $f(x) = (m_{high} + x)^e - C \pmod{N}$。由于 $f(x) \equiv 0 \pmod{N}$ 且 $x$ 是小根，可以利用 Coppersmith 定理找到 $x$。

* **Sage 脚本：**

```python
# Sage
from sage.all import *

n = Integer(0)
e = Integer(0)
c = Integer(0)
mbar = Integer(0) 
kbits = Integer(0) 

nbits = n.nbits()
print(f"明文的 {nbits - kbits} 高位 (共 {nbits} 位) 已知")

PR = PolynomialRing(Zmod(n), 'x')
f = (mbar + PR.gen())**e - c 

roots = f.small_roots(X=2**kbits, beta=1) 

if roots:
    x0 = roots[0]
    m_found = mbar + x0
    print(f"恢复的明文: {m_found}")
else:
    print("未找到小根，Coppersmith 攻击失败。")
```

#### 3.3.6 Coppersmith 攻击（已知 $d$ 的低位攻击）

如果已知私钥指数 $d$ 的部分低位，你可以恢复完整的 $d$。

* **原理：**
  这个攻击利用了 $ed = k\phi(n) + 1$ 的关系，以及 $\phi(n) = n - p - q + 1$。通过构建一个关于 $p$ 和 $k$ 的多项式，并在模 $2^{kbits}$ 下求解小根来恢复 $p$。

* **Sage 脚本：**

```python
# Sage
from sage.all import *

def partial_p(p0_val, kbits_val, n_val):
    PR = PolynomialRing(Zmod(n_val), 'x')
    f = (1 << kbits_val) * PR.gen() + p0_val
    f = f.monic()
    
    roots = f.small_roots(X=2**(n_val.nbits() // 2 - kbits_val), beta=0.4) 
    
    if roots:
        x0 = roots[0]
        p_candidate = gmpy2.gcd((1 << kbits_val) * x0 + p0_val, n_val)
        if p_candidate != 1 and p_candidate != n_val:
            return Integer(p_candidate)
    return None

def find_p_from_d0(d0_val, kbits_val, e_val, n_val):
    X = var('X') 
    
    for k_val in range(1, e_val + 1):
        f_poly_d0 = (e_val * d0_val - 1) * X - k_val * X * (n_val - X + 1) + k_val * n_val
        
        results = f_poly_d0.roots(modulus = 2**kbits_val) 
        
        for root_tuple in results:
            p0 = Integer(root_tuple[0]) 
            p = partial_p(p0, kbits_val, n_val)
            if p and p != 1:
                return p
    return None

n = Integer(0)
e = Integer(0)
c = Integer(0)
d0 = Integer(0) 

nbits = n.nbits()
kbits = d0.nbits() 

print(f"已知 d 的低 {kbits} 位 (共 {nbits} 位)")
p = find_p_from_d0(d0, kbits, e, n)

if p:
    print(f"找到 p: {p}")
    q = n//Integer(p)
    phi = (p-1)*(q-1)
    d = inverse_mod(e, phi)
    print(f"d: {d}")
else:
    print("Coppersmith 攻击（已知 d 低位）失败。")
```

#### 3.3.6.1 变种1：$n=p \cdot q \cdot r$，已知 $n, p, d=\text{inv}(e, \phi(n)), e, c$

当模数是三个素数的乘积 $n=p \cdot q \cdot r$，且已知其中一个素因子 $p$ 和 $d$ 的低位时，可以恢复 $q$ 和 $r$。

* **原理：**
  已知 $p$，则 $n' = n/p = q \cdot r$。问题转化为分解 $n'$。同时，利用已知 $d$ 的低位 $d_0$，可以推导出关于 $q$ 的同余方程，并通过 Coppersmith 攻击找到 $q$。

* **Sage 脚本：**

```python
# Sage
from sage.all import *

def find_q_from_d0(d0_val, kbits_val, e_val, n_val, p_val):
    X = var('X') 
    
    for k_val in range(1, e_val + 1): 
        k_dot = k_val * (p_val - 1)
        n_prime = n_val // p_val
        
        f_poly = e_val * d0_val * X - k_dot * X * (n_prime - X + 1) + k_dot * n_prime - X
        
        results = f_poly.roots(modulus = 2**kbits_val)
        
        for root_tuple in results:
            q_candidate = Integer(root_tuple[0])
            if n_prime % q_candidate == 0 and q_candidate != 1 and q_candidate != n_prime:
                return q_candidate
    return None

n = Integer(0)
p = Integer(0)
c = Integer(0)
d0 = Integer(0) 
e = Integer(0)
kbits = d0.nbits()

q = find_q_from_d0(d0, kbits, e, n, p)

if q:
    print(f"找到 q: {q}")
    r = (n // p) // q
    print(f"找到 r: {r}")
    
    phi = (p - 1) * (q - 1) * (r - 1)
    d = inverse_mod(e, phi)
    print(f"恢复的私钥 d: {d}")
else:
    print("Coppersmith 攻击（d 低位变种1）失败。")
```

#### 3.3.7 Coppersmith 攻击（已知 $N$ 一个因子的高位，部分 $p$）

如果你知道模数 $N$ 的一个因子（例如 $p$）的较高位时，你可以通过 Coppersmith 攻击来恢复完整的素因子。

* **原理：**
  设 $p = p_{bar} + x$，其中 $p_{bar}$ 是已知的高位部分， $x$ 是未知的小尾数。构造多项式 $f(x) = p_{bar} + x \pmod{N}$。由于 $f(x) \equiv 0 \pmod{p}$，且 $x$ 的范围较小，可以利用 Coppersmith 定理在模 $N$ 下找到 $x$。

* **Sage 脚本：**

```python
# Sage
from sage.all import *

n = Integer(0)
e = Integer(0)
c = Integer(0)
pbar = Integer(0) 
kbits = Integer(0) 

print(f"已知 N 的一个因子（p）的 {pbar.nbits() - kbits} 高位 (共 {pbar.nbits()} 位)")

PR = PolynomialRing(Zmod(n), 'x')
f = PR.gen() + pbar 

roots = f.small_roots(X=2**kbits, beta=0.4) 

if roots:
    x0 = roots[0]
    p = x0 + pbar
    if n % p == 0:
        q = n // Integer(p)
        d = inverse_mod(e, (p - 1) * (q - 1))
        print(f"找到 p: {p}")
        print(f"找到 q: {q}")
        print(f"恢复的私钥 d: {d}")
    else:
        print("找到的根不是 n 的因子。")
else:
    print("未找到小根，Coppersmith 攻击失败。")
```

---

### 3.4 基于光滑数的攻击

这类攻击利用的是某些整数（如 $p-1$ 或 $p+1$）具有较小素因子的特性。

#### 3.4.1 Pollard’s $p-1$ 方法

* **原理：**
  如果 $p-1$ 是 $B$-光滑数，意味着 $p-1$ 的所有素因子都小于或等于 $B$。那么 $B!$ 必然是 $p-1$ 的倍数。根据费马小定理，$a^{B!} \equiv 1 \pmod{p}$。因此，你可以计算 $\gcd(a^{B!} - 1, N)$。如果结果大于 $1$ 且小于 $N$，那么它就是 $p$。

* **Python 脚本：**

```python
import gmpy2 as gp

N = 0 

a = 2 

k = 2 
while True:
    a = gp.powmod(a, k, N) 
    res = gp.gcd(a - 1, N) 
    
    if res != 1 and res != N:
        q = N // res
        print(f"找到 p: {res}")
        print(f"找到 q: {q}")
        break
    
    if res == N: 
        print("遇到 N，可能需要更换基数 a 或调整 k 的策略。")
        break 
    
    k += 1 
```

#### 3.4.2 Williams’s $p+1$ 方法

* **原理：**
  与 Pollard's $p-1$ 类似，Williams's $p+1$ 算法基于 Lucas 序列，适用于分解 $N$ 的素因子 $p$，其中 $p+1$ 是一个光滑数。

---

### 3.5 基于同模性 (Common Modulus) 和中国剩余定理 (CRT) 的攻击

这类攻击利用多个加密操作共享相同模数或可以通过 CRT 组合同余式的情况。

#### 3.5.1 低加密指数广播攻击 (Hastad Attack)

当同一个消息 $M$ 被使用相同的低加密指数 $e$ 但不同的模数 $N_i$ 进行多次加密时，Hastad 攻击变得可行。

* **原理：**
  如果 $M$ 被 $k$ 个不同的模数 $N_1, \ldots, N_k$ 和相同的加密指数 $e$ 加密，得到 $C_i \equiv M^e \pmod{N_i}$。当 $e$ 足够小（通常 $e \le k$）时，可以通过中国剩余定理（CRT）将这些同余式组合起来，得到 $X = M^e \pmod{N_{prod}}$。如果 $M^e < N_{prod}$，那么 $X = M^e$，你可以直接对 $X$ 开 $e$ 次方根得到 $M$。

* **Sage 脚本：**

```python
# Sage
from sage.all import *

def chinese_remainder(modulus_list, remainders_list):
    Sum = 0
    prod_val = prod(modulus_list) 
    
    for m_i, r_i in zip(modulus_list, remainders_list):
        p = prod_val // m_i
        Sum += r_i * (inverse_mod(p, m_i) * p)
    return Sum % prod_val

n_array = [] 
c_array = [] 
e_val = Integer(0) 

m_e_val = chinese_remainder(n_array, c_array)

m = m_e_val.nth_root(e_val, truncate=True) 

if pow(m, e_val, prod(n_array)) == m_e_val:
    print(f"明文 M: {m}")
    print(f"明文字节串: {bytes.fromhex(hex(m)[2:])}")
else:
    print("Hastad 攻击失败或需要进一步处理。")
```

#### 3.5.2 共模攻击 (Common Modulus Attack)

当不同的用户共享同一个模数 $N$，但使用不同的加密指数 $e_1, e_2$ 来加密同一个消息 $M$ 时，会发生共模攻击。

* **原理：**
  已知 $N, e_1, e_2, C_1, C_2$，其中 $C_1 \equiv M^{e_1} \pmod{N}$ 和 $C_2 \equiv M^{e_2} \pmod{N}$。如果 $\gcd(e_1, e_2) = 1$，则可以找到整数 $s_1, s_2$ 使得 $s_1 e_1 + s_2 e_2 = 1$。这样， $M \equiv C_1^{s_1} \cdot C_2^{s_2} \pmod{N}$。

* **Python 脚本：**

```python
import gmpy2 as gp
import binascii

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

n = 0 
c1 = 0 
c2 = 0 
e1 = 0 
e2 = 0 

g, s1, s2 = egcd(e1, e2)

if g != 1:
    print("e1 和 e2 不互素，共模攻击可能无法直接应用。")
else:
    if s1 < 0:
        s1 = -s1
        c1 = gp.invert(c1, n)
    if s2 < 0:
        s2 = -s2
        c2 = gp.invert(c2, n)
    
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    print(binascii.unhexlify(hex(m)[2:]))
```

#### 3.5.3 $e, m$ 相同，多个 $N$ 中存在两个 $N$ 有 GCD（模不互素）

当存在多个模数 $N_i$ 加密了相同的消息 $M$（通常也使用相同的 $e$），并且其中至少有两个模数 $N_i, N_j$ 不互素（即 $\gcd(N_i, N_j) \ne 1$）时，可以利用这一弱点。

* **原理：**
  如果 $\gcd(N_i, N_j) = g > 1$，那么 $g$ 就是 $N_i$ 和 $N_j$ 的一个公共素因子。通过 $g$，你可以很容易地分解 $N_i = g \cdot (N_i/g)$ 和 $N_j = g \cdot (N_j/g)$，从而得到所有相关的素因子 $p, q$ 并破解 RSA。

* **Python 脚本：**

```python
import gmpy2 as gp
import binascii

n_list = [] 
e = 0
c = 0 

p_found = None
q_found = None
target_n = None

for i in range(len(n_list)):
    for j in range(i + 1, len(n_list)):
        current_n1 = n_list[i]
        current_n2 = n_list[j]
        
        common_divisor_gcd = gp.gcd(current_n1, current_n2)
        
        if common_divisor_gcd != 1 and common_divisor_gcd != current_n1 and common_divisor_gcd != current_n2:
            p_found = common_divisor_gcd
            if current_n1 % p_found == 0:
                q_found = current_n1 // p_found
                target_n = current_n1 
                break
            elif current_n2 % p_found == 0:
                q_found = current_n2 // p_found
                target_n = current_n2 
                break
    if p_found and q_found:
        break

if p_found and q_found and target_n:
    print(f"找到公共素因子 p: {p_found}")
    print(f"对应另一个素因子 q: {q_found}")
    print(f"分解的模数 N: {target_n}")
    
    phi = (p_found - 1) * (q_found - 1)
    d = gp.invert(e, phi)
    m = pow(c, d, target_n) 
    
    print(binascii.unhexlify(hex(m)[2:]))
else:
    print("未找到共模因子或无法分解。")
```

#### 3.5.4 Coppersmith's Short-pad Attack & Related Message Attack (Franklin-Reiter 攻击)

当加密消息 $M$ 进行了短填充（padding）时，或者两个具有线性关系的消息 $M_1, M_2$ 使用同一个公钥加密时，可能受到此攻击。

* **原理：**
  **Short-pad Attack:** 如果消息 $M$ 的有效部分很短，即 $M < N^{1/e}$，那么 $M^e - C \equiv 0 \pmod{N}$ 的多项式 $f(x) = x^e - C$ 会存在一个小的根 $M$，可以被 Coppersmith 定理找到。
  **Related Message Attack (Franklin-Reiter Attack):** 如果两个消息 $M_1, M_2$ 之间存在线性关系，例如 $M_1 = aM_2 + b \pmod{N}$，且使用相同的公钥 $(N, e)$ 加密，得到 $C_1, C_2$。你可以构造两个多项式 $g_1(x) = x^e - C_1$ 和 $g_2(x) = (ax+b)^e - C_2$。它们的公共根就是 $M_2$。

* **Sage 脚本1：** (Franklin-Reiter 攻击)

```python
# Sage
from sage.all import *
import binascii

def attack_franklin_reiter(c1_val, c2_val, n_val, e_val, a_val, b_val, c_val_coeff, d_val_coeff):
    PR = PolynomialRing(Zmod(n_val), 'x') 
    
    g1_poly = (a_val * PR.gen() + b_val)**e_val - c1_val
    g2_poly = (c_val_coeff * PR.gen() + d_val_coeff)**e_val - c2_val

    def poly_gcd(p1, p2):
        while p2:
            p1, p2 = p2, p1 % p2
        return p1
    
    gcd_poly = poly_gcd(g1_poly, g2_poly)
    roots = gcd_poly.roots()
    
    if roots:
        return roots[0][0] 
    return None

c1 = 0 
c2 = 0 
n = 0 
e = 0 

a_val_param = 1
b_val_param = 0
c_val_coeff_param = 1
d_val_coeff_param = 0

m1 = attack_franklin_reiter(c1, c2, n, e, a_val_param, b_val_param, c_val_coeff_param, d_val_coeff_param)

if m1:
    print(binascii.unhexlify(hex(m1)[2:]))
else:
    print("Franklin-Reiter 攻击失败。")
```

* **Sage 脚本2：** (Short-pad 和 Related Message 攻击的组合)

```python
# Sage
from sage.all import *

def short_pad_attack_diff(c1_val, c2_val, e_val, n_val):
    PRxy = PolynomialRing(Zmod(n_val), 'x, y')
    PRx = PolynomialRing(Zmod(n_val), 'xn')
    PRZZ = PolynomialRing(Zmod(n_val), 'xz, yz') 
    
    g1 = PRxy.gen(0)**e_val - c1_val
    g2 = (PRxy.gen(0) + PRxy.gen(1))**e_val - c2_val
    
    q1 = g1.change_ring(PRZZ)
    q2 = g2.change_ring(PRZZ)
    
    h = q2.resultant(q1, PRZZ.gen(0)) 
    h = h.univariate_polynomial() 
    h = h.change_ring(PRx).subs(PRx.gen(), PRx.gen()) 
    h = h.monic() 
    
    kbits = n_val.nbits() // (2 * e_val**2) 
    diff_roots = h.small_roots(X=2**kbits, beta=0.4) 
    
    if diff_roots:
        return diff_roots[0] 
    return None

def related_message_attack(c1_val, c2_val, diff_val, e_val, n_val):
    PRx = PolynomialRing(Zmod(n_val), 'x')
    
    g1 = PRx.gen()**e_val - c1_val
    g2 = (PRx.gen() + diff_val)**e_val - c2_val
    
    def poly_gcd(p1, p2):
        while p2:
            p1, p2 = p2, p1 % p2
        return p1
    
    gcd_poly = poly_gcd(g1, g2)
    roots = gcd_poly.roots()
    
    if roots:
        return roots[0][0] 
    return None

n = 0 
e = 0 
c1 = 0 
c2 = 0 

diff = short_pad_attack_diff(c1, c2, e, n)
if diff is not None:
    print(f"两个消息的差异为: {diff}")
    
    m1 = related_message_attack(c1, c2, diff, e, n)
    if m1 is not None:
        print(f"恢复的 M1: {m1}")
        m2 = (m1 + diff) % n 
        print(f"恢复的 M2: {m2}")
    else:
        print("相关消息攻击失败，未能恢复明文。")
else:
    print("短填充攻击失败，未能找到消息差异。")
```

#### 3.5.4.1 变种1：$e$ 较大

当加密指数 $e$ 较大时，计算多项式结式的复杂度会很高。这时可以考虑使用 Half-GCD 算法来降低计算结式的时间复杂度。

#### 3.5.4.2 变种2：$c_i=(a_i m+b_i)^e \pmod{n_i}$

当存在多个密文 $c_i$，每个密文都对应于一个线性变换后的消息 $(a_i m+b_i)$，并使用不同的模数 $n_i$ 和相同的加密指数 $e$ 加密时。

* **原理：**
  你可以利用中国剩余定理（CRT）构造一个统一的多项式 $f(x) = \sum_i T_i \cdot ((a_i x + b_i)^e - c_i) \pmod{\prod n_i}$。如果 $M < (\prod n_i)^{1/\deg(f(x))}$，那么 $M$ 是 $f(x)$ 的一个小根，可以利用 Coppersmith 攻击找到 $M$。

#### 3.5.5 RSA Hastad Attack with non-linear padding and different public keys（带非线性padding和不同公钥的广播攻击）

这种攻击场景是 Hastad 攻击的更复杂变种，其中消息 $M$ 经过了非线性填充。

* **原理：**
  如果消息 $M$ 经过了非线性填充（例如 $M^2 + K$），并且被多个不同的 $(N_i, e_i)$ 密钥对加密，且 $e_i$ 较小。同样，你可以利用 CRT 结合 Coppersmith 定理来解决。

* **Sage 脚本：**

```python
# Sage
from sage.all import *

def linearPaddingHastads(c_array, n_array, a_array, b_array, e_array, eps):
    if not (len(c_array) == len(n_array) == len(a_array) == len(b_array) == len(e_array)):
        print("输入数组长度不一致！")
        return -1

    c_array = [Integer(c) for c in c_array]
    n_array = [Integer(n) for n in n_array]
    a_array = [Integer(a) for a in a_array]
    b_array = [Integer(b) for b in b_array]
    e_array = [Integer(e) for e in e_array]

    prod_n = prod(n_array)
    
    TArray = []
    for i in range(len(n_array)):
        array_to_crt = [0] * len(n_array)
        array_to_crt[i] = 1
        TArray.append(crt(array_to_crt, n_array))
    
    PR = PolynomialRing(Zmod(prod_n), 'x')
    g_array = []
    for i in range(len(n_array)):
        f_i_x = a_array[i] * PR.gen()**2 + b_array[i] 
        g_array.append(TArray[i] * (f_i_x**e_array[i] - c_array[i]))
    
    g_sum = sum(g_array) 
    g_sum = g_sum.monic() 
    
    roots = g_sum.small_roots(epsilon=eps) 
    
    if not roots:
        print("未找到解！")
        return -1
    return roots

def nonLinearPaddingAttack_main():
    e_arr = [3, 3, 3, 3] 
    n_arr = [] 
    c_arr = [] 
    a_arr = [1, 1, 1, 1] 
    b_arr = [Integer(k_val) * (3**431) for k_val in [3, 8, 10, 11]] 
    
    msg_roots = linearPaddingHastads(c_arr, n_arr, a_arr, b_arr, e_arr, eps=Integer(1)/20) 
    
    if msg_roots != -1:
        for i, root_val in enumerate(msg_roots):
            print(f"找到明文候选 {i+1}: {root_val}")

nonLinearPaddingAttack_main()
```

---

### 3.6 基于预言机 (Oracle) 的攻击

这类攻击不依赖于密钥参数的泄露，而是通过与加密/解密预言机（Oracle）的交互来恢复信息。

#### 3.6.1 选择明文攻击 (Chosen-Plaintext Attack)

如果你可以选择任意明文并获得其 RSA 加密结果，则可能推导出模数 $N$。

* **原理：**
  1.  选择明文 $M_1$，获得 $C_1 = M_1^e \pmod{N}$。
  2.  选择 $M_2 = M_1^2$，获得 $C_2 = M_2^e = (M_1^2)^e = (M_1^e)^2 = C_1^2 \pmod{N}$。
  3.  因此 $C_1^2 - C_2 \equiv 0 \pmod{N}$，这意味着 $C_1^2 - C_2 = k \cdot N$。
  4.  通过计算多个这样的 $k \cdot N$ 值的**最大公约数 (GCD)**，可以恢复 $N$。

* **Python 脚本：**

```python
import gmpy2
from Cryptodome.Util.number import getPrime

def server_encode(plaintext_val, e_val_sim, n_val_sim):
    return pow(plaintext_val, e_val_sim, n_val_sim)

def get_n_from_cpa(e_sim, n_sim):
    n_set = []
    
    c2 = server_encode(2, e_sim, n_sim)
    c4 = server_encode(4, e_sim, n_sim)
    c8 = server_encode(8, e_sim, n_sim)
    n_set.append(c2 * c2 - c4)
    n_set.append(c4 * c2 - c8) 
    
    c3 = server_encode(3, e_sim, n_sim)
    c9 = server_encode(9, e_sim, n_sim)
    c27 = server_encode(27, e_sim, n_sim)
    n_set.append(c3 * c3 - c9)
    n_set.append(c9 * c3 - c27)
    
    c5 = server_encode(5, e_sim, n_sim)
    c25 = server_encode(25, e_sim, n_sim)
    c125 = server_encode(125, e_sim, n_sim)
    n_set.append(c5 * c5 - c25)
    n_set.append(c5 * c5 * c5 - c125)
    
    if not n_set:
        return None
    
    n_recovered = n_set[0]
    for x_val in n_set:
        n_recovered = gmpy2.gcd(x_val, n_recovered)
    
    while n_recovered % 2 == 0 and n_recovered > 0:
        n_recovered //= 2
    while n_recovered % 3 == 0 and n_recovered > 0:
        n_recovered //= 3
    while n_recovered % 5 == 0 and n_recovered > 0:
        n_recovered //= 5
        
    print(f"恢复的 N = {n_recovered}")
    return n_recovered
```

#### 3.6.2 选择密文攻击 (Chosen-Ciphertext Attack)

如果你可以构造任意密文并获得其解密结果，则可能恢复原始密文的明文。

* **原理：**
  假设你有一个密文 $C$ 且知道其对应的公钥 $(N, e)$。
  1.  选择一个随机数 $X$，满足 $1 < X < N$ 且 $\gcd(X, N) = 1$。
  2.  计算派生密文 $Y = (C \cdot X^e) \pmod{N}$。
  3.  将 $Y$ 发送给解密预言机，获得解密结果 $Z = Y^d \pmod{N}$。
  4.  由于 $Z \equiv (C \cdot X^e)^d \equiv C^d \cdot X \equiv M \cdot X \pmod{N}$。
  5.  因此 $M \equiv Z \cdot X^{-1} \pmod{N}$。通过计算 $X$ 的模逆元，可以恢复原始明文 $M$。

* **Python 脚本：**

```python
from Cryptodome.Util.number import getPrime, long_to_bytes
import gmpy2

def server_decode(ciphertext_val, d_val_sim, n_val_sim):
    return pow(ciphertext_val, d_val_sim, n_val_sim)

def get_m_from_cca(c_val, e_val, n_val, d_sim):
    X_val = getPrime(n_val.bit_length() // 8) 
    while gmpy2.gcd(X_val, n_val) != 1:
        X_val = getPrime(n_val.bit_length() // 8)
    
    Y_val = (c_val * pow(X_val, e_val, n_val)) % n_val
    
    Z_val = server_decode(Y_val, d_sim, n_val)
    
    X_inv = gmpy2.invert(X_val, n_val)
    
    M_recovered = (Z_val * X_inv) % n_val
    
    print(f"恢复的明文整数: {M_recovered}")
    try:
        print(f"恢复的明文字节串: {long_to_bytes(M_recovered)}")
    except Exception as e_inner:
        print(f"解码明文字节串失败: {e_inner}")
        
    return M_recovered
```

---

## 总结

RSA 算法的安全性严重依赖于大整数分解的困难性。然而，当密钥参数（如 $p, q, d$）泄露部分信息，或者当算法在使用中存在特定缺陷（如低指数、模数共享、填充不足）时，RSA 可能面临多种攻击。理解这些攻击背后的数学原理，对于设计更安全的密码系统和防御潜在威胁至关重要。

## Reference

- lazzzaro
