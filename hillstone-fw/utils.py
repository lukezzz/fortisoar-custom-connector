def addr2dec(addr):
    """将点分十进制IP地址转换成十进制整数"""
    items = [int(x) for x in addr.split(".")]
    return sum([items[i] << [24, 16, 8, 0][i] for i in range(4)])


def dec2addr(dec):
    """将十进制整数IP转换成点分十进制的字符串IP地址"""
    return ".".join([str(dec >> x & 0xFF) for x in [24, 16, 8, 0]])


if __name__ == "__main__":
    print(addr2dec("123.1.1.1"))
