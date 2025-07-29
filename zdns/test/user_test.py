#!/usr/bin/python3/bin/python3
# coding=utf-8

import http.client
import json
import ssl
import logging

# 创建忽略 SSL 验证的上下文
context = ssl._create_unverified_context()

# 设置日志记录
logging.basicConfig(
    filename="api_requests.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def create_gmember(api_host, api_port, dc_name, gmember_name, ip, port):
    try:
        # 创建 gmember 请求
        payload = json.dumps(
            {
                "gmember_name": gmember_name,
                "ip": ip,
                "port": port,
                "hms": [],
                "linkid": "",
                "preferred": "",
                "alternate": "",
                "enable": "yes",
            }
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Basic YWRtaW46c2VjcmV0",  # 示例Authorization, 替换为实际值
            "Accept": "*/*",
            "Host": f"{api_host}:{api_port}",
            "Connection": "keep-alive",
        }

        conn = http.client.HTTPSConnection(api_host, api_port, context=context)
        conn.request("POST", f"/dc/{dc_name}/gmember", payload, headers)
        res = conn.getresponse()
        data = res.read().decode("utf-8")

        # 记录响应
        logging.info(f"gmember {gmember_name} response: {data}")
        return data
    except Exception as e:
        error_msg = f"Error creating gmember {gmember_name}: {str(e)}"
        logging.error(error_msg)
        return error_msg


def create_gpool(api_host, api_port, gpool_name, gmembers):
    try:
        # 创建 gpool 请求
        gmember_list = []
        for gm in gmembers:
            gmember_list.append(
                {
                    "dc_name": gm["dc_name"],
                    "gmember_name": gm["gmember_name"],
                    "ratio": gm["ratio"],
                    "enable": gm["enable"],
                }
            )

        payload = json.dumps(
            {
                "name": gpool_name,
                "ttl": "10",
                "type": "A",
                "max_addr_ret": "1",
                "hm_gm_flag": "yes",
                "hms": [],
                "hm_gool_flag": "no",
                "warning": "yes",
                "first_algorithm": "sp",
                "second_algorithm": "none",
                "gmember_list": gmember_list,
                "enable": "yes",
            }
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Basic YWRtaW46c2VjcmV0",
            "Accept": "*/*",
            "Host": f"{api_host}:{api_port}",
            "Connection": "keep-alive",
        }

        conn = http.client.HTTPSConnection(api_host, api_port, context=context)
        conn.request("POST", "/gpool", payload, headers)
        res = conn.getresponse()
        data = res.read().decode("utf-8")

        # 记录响应
        logging.info(f"gpool {gpool_name} response: {data}")
        return data
    except Exception as e:
        error_msg = f"Error creating gpool {gpool_name}: {str(e)}"
        logging.error(error_msg)
        return error_msg


def create_dzone(api_host, api_port, dzone_name, gpool_name):
    try:
        # 创建 dzone 请求
        payload = json.dumps(
            {
                "name": dzone_name.split(".")[0],
                "type": "A",
                "algorithm": "rr",
                "gpool_list": [{"id": "_id6", "gpool_name": gpool_name, "ratio": "1"}],
                "last_resort_pool": "",
                "fail_policy": "return_to_dns",
                "enable": "yes",
            }
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Basic YWRtaW46c2VjcmV0",
            "Accept": "*/*",
            "Host": f"{api_host}:{api_port}",
            "Connection": "keep-alive",
        }

        conn = http.client.HTTPSConnection(api_host, api_port, context=context)
        if "fullgoal.com.cn" in dzone_name:
            domain_name = "fullgoal.com.cn."
        else:
            domain_name = "fuguo."
        conn.request(
            "POST", "/views/ADD/dzone/{}/gmap".format(domain_name), payload, headers
        )
        res = conn.getresponse()
        data = res.read().decode("utf-8")

        # 记录响应
        logging.info(f"dzone {dzone_name} response: {data}")
        return data
    except Exception as e:
        error_msg = f"Error creating dzone {dzone_name}: {str(e)}"
        logging.error(error_msg)
        return error_msg


def process_input_from_file(file_path, api_host, api_port):
    # 从文件中读取数据并处理
    with open(file_path, "r") as file:
        lines = file.readlines()

    for line in lines:
        # 打印出每一行的数据进行调试
        print(f"Processing line: {line.strip()}")

        parts = line.strip().split(",")
        if len(parts) < 2:
            logging.error(f"Invalid format in line: {line.strip()}")
            continue  # 如果格式不对跳过该行

        dzone_name = parts[0]
        gmembers = parts[1:]

        # 创建 gmember 请求
        gmember_list = []
        for gmember in gmembers:
            try:
                # 调试：输出 gmember 的内容
                print(f"Processing gmember: {gmember}")

                # 检查是否包含多个冒号，分割为两部分：dc_name 和 ip:port
                if gmember.count(":") == 2:
                    dc_name, ip, port = gmember.split(":")
                elif gmember.count(":") == 1:
                    dc_name, ip_port = gmember.split(":")
                    ip, port = ip_port.split(":")  # 进一步拆分 IP 和端口
                else:
                    raise ValueError(f"Invalid gmember format: {gmember}")

                gmember_name = f"{dc_name}_{ip}"  # 自定义命名规则
                gmember_response = create_gmember(
                    api_host, api_port, dc_name, gmember_name, ip, port
                )
                gmember_list.append(
                    {
                        "dc_name": dc_name,
                        "gmember_name": gmember_name,
                        "ratio": 1,
                        "enable": "yes",
                    }
                )

            except Exception as e:
                error_msg = f"Error processing gmember {gmember}: {str(e)}"
                logging.error(error_msg)
                continue  # 跳过此 gmember，继续处理下一个

        # 生成 gpool_name，替换域名中的 . 为 _
        if "fullgoal.com.cn" in dzone_name:
            domain_name = "fullgoal.com.cn."
        else:
            domain_name = "fuguo."
        domain_name_list = dzone_name.split(".")
        domain_name_list = list(filter(None, domain_name_list))
        gpool_name = ("_").join(domain_name_list) + "_pool"
        # gpool_name = dzone_name.replace('.', '_') + "_pool"
        print(f"Generated gpool_name: {gpool_name}")

        # 创建 gpool 和 dzone 请求
        gpool_response = create_gpool(api_host, api_port, gpool_name, gmember_list)
        dzone_response = create_dzone(api_host, api_port, dzone_name, gpool_name)

        # 将结果保存到文件
        with open("api_requests_results.txt", "a") as result_file:
            result_file.write(f"DZone: {dzone_name}, GPool: {gpool_name}\n")
            result_file.write(f"GMember Responses: {gmember_response}\n")
            result_file.write(f"GPool Response: {gpool_response}\n")
            result_file.write(f"DZone Response: {dzone_response}\n")
            result_file.write("=" * 50 + "\n")


# 传入用户文件路径、API 地址和端口
file_path = "user_input_fuguo.txt"  # 示例文件路径
api_host = "172.16.66.43"  # 用户自定义API主机
api_port = 8000  # 用户自定义API端口

process_input_from_file(file_path, api_host, api_port)
