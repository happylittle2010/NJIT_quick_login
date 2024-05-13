import getpass
import json
import logging
import msvcrt
import os
import os.path as osp
import random
import sys
import time
import winreg
from logging.handlers import TimedRotatingFileHandler
from urllib.parse import urlparse, parse_qs

import requests
import winshell
from DrissionPage import ChromiumOptions
from DrissionPage import ChromiumPage
from DrissionPage.errors import PageDisconnectedError

from broswer_finder import get_browser_path
from welcome_ascii_art import get_welcome_ascii_art


def get_logger():
    # 配置日志
    config_dir = get_config_dir(do_not_log=True)
    log_file_dir = osp.join(config_dir, "log")
    os.makedirs(log_file_dir, exist_ok=True)  # 确保目录存在
    log_file_path = os.path.join(log_file_dir, 'app.log')

    # 创建一个TimedRotatingFileHandler，每天创建一个新的日志文件
    handler = TimedRotatingFileHandler(log_file_path, when='midnight', interval=1, backupCount=30, encoding='utf-8')
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return logger


def get_config_dir(do_not_log=False):
    if do_not_log:
        # 获取用户目录
        user_dir = os.path.expanduser("~")

        # 检查目标目录是否存在
        config_dir = osp.join(user_dir, "happylittle", "njit_quick_login")

        # 如果目录不存在，则创建目录
        if not osp.exists(config_dir):
            os.makedirs(config_dir)
    else:
        # 获取用户目录
        user_dir = os.path.expanduser("~")
        logger.debug(f"get_config_dir(): 获取用户目录：{user_dir}")

        # 检查目标目录是否存在
        config_dir = osp.join(user_dir, "happylittle", "njit_quick_login")
        logger.debug(f"get_config_dir(): 检查目标目录是否存在：{config_dir}")

        # 如果目录不存在，则创建目录
        if not osp.exists(config_dir):
            os.makedirs(config_dir)
            logger.info(f"get_config_dir(): 目录不存在，创建目录：{config_dir}")
        else:
            logger.debug(f"get_config_dir(): 目录已存在：{config_dir}")

    return config_dir


def get_config_file_path(config_file_name):
    config_dir = get_config_dir()
    config_file_path: str = osp.join(config_dir, config_file_name)
    logger.debug(f"get_config_file_path(): 获取配置文件路径：{config_file_path}")

    return config_file_path


def delete_config_file(config_file_name: str):
    config_file_path = get_config_file_path(config_file_name)
    if osp.exists(config_file_path):
        logger.info(f"delete_config_file(): 删除配置文件：{config_file_path}")
        os.remove(config_file_path)


def build_config(
        user_account,
        user_password,
        last_run_drission_page_time,
        target_url,
        params,
        headers,
        created_desktop_shortcut,
        asked_startup_permission,
        created_startup_shortcut,
        asked_desktop_shortcut_permission,
):
    return {
        "user_account": user_account,
        "user_password": user_password,
        "last_run_drission_page_time": last_run_drission_page_time,
        "target_url": target_url,
        "params": params,
        "headers": headers,
        "created_desktop_shortcut": created_desktop_shortcut,
        "asked_startup_permission": asked_startup_permission,
        "created_startup_shortcut": created_startup_shortcut,
        "asked_desktop_shortcut_permission": asked_desktop_shortcut_permission,
    }


def read_config_file(config_file_name: str):
    config_file_path = get_config_file_path(config_file_name)
    if osp.exists(config_file_path):  # 存在配置文件
        logger.info(f"read_config_file(): 非首次使用，读取配置文件：{config_file_path}")
        is_first_time_use = False
        with open(config_file_path, "r") as f:
            config = json.load(f)
            logger.info(f"read_config_file(): 读取配置文件内容：{config}")
    else:
        # 首次运行，初始化配置文件
        logger.info(f"read_config_file(): 首次使用，创建配置文件：{config_file_path}")
        colour_print("首次使用，尚未保存您的账号信息，请输入账号密码：", "cyan")
        user_account = input("账号：")
        user_password = input("密码：")
        is_first_time_use = True

        config = build_config(
            user_account=user_account,
            user_password=user_password,
            last_run_drission_page_time=0,
            target_url=None,
            params=None,
            headers=None,
            created_desktop_shortcut=False,
            asked_startup_permission=False,
            created_startup_shortcut=False,
            asked_desktop_shortcut_permission=False,
        )

        with open(config_file_path, "w") as f:
            json.dump(config, f)
            logger.info(f"read_config_file(): 保存配置文件：{config}")
    return config, is_first_time_use


def save_config_file(config):
    config_file_path = get_config_file_path(config_file_name)
    if osp.exists(config_file_path):
        with open(config_file_path, "w") as f:
            logger.info(f"save_config_file(): 配置文件内容：{config}")
            logger.info(f"save_config_file(): 保存配置文件到：{config_file_path}")
            json.dump(config, f)
    else:
        colour_print("配置文件不存在，保存配置文件失败！", "red")
        logger.critical("save_config_file(): 配置文件不存在，保存配置文件失败！")
        press_any_key_to_exit(is_auto_exit=False)


def create_shortcut(bin_path: str, shortcut_path: str, desc: str):
    """
    这里调用了winshell的CreateShortcut函数。
    :param bin_path: exe路径
    :param shortcut_path: 需要创建快捷方式的路径
    :param desc: 描述，鼠标放在图标上面会有提示
    :return:
    """
    try:
        shortcut = shortcut_path + ".lnk"
        winshell.CreateShortcut(
            Path=shortcut, Target=bin_path, Icon=(bin_path, 0), Description=desc
        )
        logger.info(f"create_shortcut(): 为 {bin_path} 创建快捷方式 {shortcut}")
        return True
    except ImportError as e:
        colour_print(f"创建快捷方式失败！错误原因：{str(e)}", "red")
        logger.error(f"create_shortcut(): 创建快捷方式失败！错误原因：{str(e)}")
    return False


def get_desktop_path():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        )
        desktop_path = winreg.QueryValueEx(key, "Desktop")[0]
        logger.info(f"get_desktop_path(): 获取桌面路径：{desktop_path}")
        return desktop_path
    except Exception as e:
        colour_print(f"获取桌面路径失败！错误原因：{str(e)}", "red")
        logger.error(f"get_desktop_path(): 获取桌面路径失败！错误原因：{str(e)}")


def get_startup_path():
    try:
        syspath = os.getenv("SystemDrive")  # 系统盘符名称
        username = getpass.getuser()  # 获取用户名
        # 自启动目录
        startup_path = os.path.join(
            syspath,
            r"\users",
            username,
            r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        )
        return startup_path
    except Exception as e:
        colour_print(f"获取自启动目录失败！错误原因：{str(e)}", "red")
        logger.error(f"get_startup_path(): 获取自启动目录失败！错误原因：{str(e)}")


def add_shortcut_to_desktop(program_name: str, program_desc: str):
    try:
        desktop_dir = get_desktop_path()
        bin_path = sys.argv[0]  # 获取自身路径
        shortcut_path = desktop_dir + f"\\{program_name}"
        create_shortcut(bin_path=bin_path, shortcut_path=shortcut_path, desc=program_desc)
    except Exception as e:
        colour_print(f"添加桌面快捷方式失败！错误原因：{str(e)}", "red")
        logger.error(f"add_shortcut_to_desktop(): 添加桌面快捷方式失败！错误原因：{str(e)}")


def add_to_startup(program_name: str, program_desc: str):
    """
    将快捷方式添加到自启动目录
    """
    try:
        startup_path = get_startup_path()
        bin_path = sys.argv[0]  # 获取自身路径
        shortcut_path = startup_path + f"\\{program_name}"
        create_shortcut(bin_path=bin_path, shortcut_path=shortcut_path, desc=program_desc)
    except Exception as e:
        colour_print(f"添加自启动失败！错误原因：{str(e)}", "red")
        logger.error(f"add_to_startup(): 添加自启动失败！错误原因：{str(e)}")


def colour_print(text, colour):
    if colour == "red":
        print("\033[31m" + text + "\033[0m")
    elif colour == "green":
        print("\033[32m" + text + "\033[0m")
    elif colour == "yellow":
        print("\033[33m" + text + "\033[0m")
    elif colour == "blue":
        print("\033[34m" + text + "\033[0m")
    elif colour == "purple":
        print("\033[35m" + text + "\033[0m")
    elif colour == "cyan":
        print("\033[36m" + text + "\033[0m")
    elif colour == "white":
        print("\033[37m" + text + "\033[0m")


def colour_print_no_new_line(text, colour):
    if colour == "red":
        print("\033[31m" + text + "\033[0m", end="")
    elif colour == "green":
        print("\033[32m" + text + "\033[0m", end="")
    elif colour == "yellow":
        print("\033[33m" + text + "\033[0m", end="")
    elif colour == "blue":
        print("\033[34m" + text + "\033[0m", end="")
    elif colour == "purple":
        print("\033[35m" + text + "\033[0m", end="")
    elif colour == "cyan":
        print("\033[36m" + text + "\033[0m", end="")
    elif colour == "white":
        print("\033[37m" + text + "\033[0m", end="")


def press_any_key_to_exit(is_auto_exit=True):
    if is_auto_exit:
        auto_exit_timeout = 3
        start_time = time.time()
        print(f"\n请按任意键退出（{auto_exit_timeout}秒后自动退出）...")
        while True:
            if msvcrt.kbhit():
                msvcrt.getch()  # 清除输入缓冲区
                break
            elif time.time() - start_time > auto_exit_timeout:
                break
            else:
                print(
                    f"{auto_exit_timeout - int(time.time() - start_time)}秒后自动退出..."
                )
                time.sleep(1)  # 稍作等待，避免过度占用CPU
        logger.info("程序正常退出。（自动退出）")
        logger.info("\n")
        sys.exit()
    else:
        colour_print("请按任意键退出...", "yellow")
        while True:
            if msvcrt.kbhit():
                msvcrt.getch()  # 清除输入缓冲区
                break
            else:
                time.sleep(1)  # 稍作等待，避免过度占用CPU
        logger.info("程序正常退出。（手动按键退出）")
        logger.info("\n")
        sys.exit()


def get_drission_page(retry_count=0, max_retries=3, retry_delay=5):
    if retry_count >= max_retries:
        colour_print("尝试调用浏览器次数过多！", "red")
        logger.error("get_drission_page(): 调用浏览器重试次数过多！重试次数：{retry_count}, 最大重试次数：{max_retries}")
        return None

    login_page = "http://172.31.255.156/a79.htm"

    colour_print("尝试调用浏览器...", "cyan")
    # 尝试调用浏览器访问网页
    try:
        logger.info("get_drission_page(): 尝试使用DrissionPage调用浏览器...")
        page = ChromiumPage()
        page.get(login_page, timeout=10)
        return page
    except FileNotFoundError:
        # DrissionPage库没有找到浏览器，尝试使用browser_finder库查找浏览器
        logger.error("get_drission_page(): DrissionPage库没有找到浏览器，尝试搜索Edge、360浏览器")
        edge_path = get_browser_path("edge")
        chrome_path = get_browser_path("chrome")
        browser360_path = get_browser_path("360")
        # 如果chrome_path和edge_path都为None，说明没有找到浏览器
        if chrome_path is None and edge_path is None and browser360_path is None:
            logger.info("get_drission_page(): 未找到任何浏览器！")
            colour_print(
                "你的电脑未安装适合的浏览器，请安装Microsoft Edge浏览器或Google Chrome浏览器后重试",
                "red",
            )
            return None
        else:
            if edge_path:
                browser_path = edge_path
            elif chrome_path:
                browser_path = chrome_path
            elif browser360_path:
                browser_path = browser360_path
            logger.info(f"get_drission_page(): 找到浏览器：{browser_path}")
    except PageDisconnectedError as e:
        colour_print(f"连接浏览器失败，错误信息：{str(e)}", "red")
        logger.error(f"get_drission_page(): 连接浏览器失败，错误信息：{str(e)}")
        colour_print(f"将在 {retry_delay} 秒后重试...", "yellow")
        time.sleep(retry_delay)
        page = get_drission_page(
            retry_count=retry_count + 1, retry_delay=retry_delay + 5
        )
        return page
    except Exception as e:
        colour_print(f"发生未知错误：{str(e)}", "red")
        logger.critical(f"get_drission_page(): 发生未知错误：{str(e)}")
        return None

    try:
        logger.info(f"get_drission_page(): 使用DrissionPage调用浏览器：{browser_path}")
        co = ChromiumOptions().set_browser_path(browser_path)
        page = ChromiumPage(co)
        page.get(login_page, timeout=10)
        return page
    except FileNotFoundError:
        logger.critical("get_drission_page(): 未找到浏览器！")
        colour_print(
            "你的电脑未安装适合的浏览器，请安装Microsoft Edge浏览器或Google Chrome浏览器后重试",
            "red",
        )
        return None
    except PageDisconnectedError as e:
        logger.error(f"get_drission_page(): 连接浏览器失败，错误信息：{str(e)}")
        colour_print(f"连接浏览器失败，错误信息：{str(e)}", "red")
        colour_print(f"将在 {retry_delay} 秒后重试...", "yellow")
        time.sleep(retry_delay)
        page = get_drission_page(
            retry_count=retry_count + 1, retry_delay=retry_delay + 5
        )
        return page
    except Exception as e:
        logger.critical(f"get_drission_page(): 发生未知错误：{str(e)}")
        colour_print(f"发生未知错误：{e}", "red")
        delete_config_file(config_file_name)
        return None


def check_connection() -> str:
    logger.info("check_connection(): 检查网络连接...")
    colour_print("正在检查网络连接...", "cyan")
    # 网址列表
    generate_204_list = [
        "http://connect.rom.miui.com/generate_204",
        "http://connectivitycheck.platform.hicloud.com/generate_204",
        "http://wifi.vivo.com.cn/generate_204",
        "http://204.ustclug.org/",
        "http://www.qualcomm.cn/generate_204"
    ]

    tested_urls = []  # 用于跟踪已测试的URL

    while len(tested_urls) < len(generate_204_list):
        # 从列表中随机选择一个未测试的URL
        untested_urls = [url for url in generate_204_list if url not in tested_urls]
        url = random.choice(untested_urls)
        tested_urls.append(url)  # 将URL添加到已测试集合中

        try:
            response = requests.get(url, timeout=1)
            logger.info(f"check_connection(): 请求{url}")
            # 如果返回204状态码，联网成功
            if response.status_code == 204:
                logger.info(f"check_connection(): 状态码：{response.status_code}，响应：{response.text}，联网成功")
                colour_print("可以正常连接网络。", "green")
                return "Success"
            # 如果返回的文本包含“Authentication is required”，联网失败
            elif "Authentication is required" in response.text:
                logger.info(f"check_connection(): 状态码：{response.status_code}，响应：{response.text}，需要认证")
                colour_print("联网失败，需要认证。", "yellow")
                return "Need authentication"
            else:
                logger.error(f"check_connection(): 状态码：{response.status_code}，响应：{response.text}，出现意外情况！")
                colour_print("出现意外情况！", "red")
                return "Failed"
        except requests.RequestException as e:
            logger.error(f"check_connection(): 请求{url}时发生异常：{e}")
            colour_print(f"请求{url}时发生异常：{e}", "red")
            return "Failed"


def parse_request_url(request_url: str, user_account: str, user_password: str):
    # 解析URL
    logger.info(f"parse_request_url(): 解析URL：{request_url}")
    parsed_url = urlparse(request_url)

    # 从查询字符串中提取参数到字典
    query_params = parse_qs(parsed_url.query)
    params = {}
    for k, v in query_params.items():
        k_is_user_account = k != "user_account"
        k_is_user_password = k != "user_password"
        if k_is_user_account and k_is_user_password:
            params[k] = v[0]

    params["user_account"] = user_account
    params["user_password"] = user_password

    target_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
    logger.info(f"parse_request_url(): 解析到参数：{params}")
    logger.info(f"parse_request_url(): 解析到目标URL：{target_url}")
    return target_url, params


def use_drission_page_login(
        user_account: str,
        user_password: str,
        retry_count=0,
        max_retries=5,
):
    if retry_count >= max_retries:
        logger.error(f"use_drission_page_login(): 登录尝试次数过多！，重试次数：{retry_count}, 最大重试次数：{max_retries}")
        colour_print("登录尝试次数过多！", "red")
        press_any_key_to_exit(is_auto_exit=False)
        return

    colour_print("正在模拟人工操作浏览器登录认证系统...", "cyan")
    logger.info("use_drission_page_login(): 尝试使用DrissionPage登录认证系统...")

    page = get_drission_page()
    if page is None:
        logger.critical("use_drission_page_login(): 未获取到DrissionPage对象！")
        press_any_key_to_exit(is_auto_exit=False)

    retry_delay = 5
    page_get_max_retries = 5
    for _ in range(page_get_max_retries):
        # 跳转到登录页面
        connection_result = page.get("http://172.31.255.156/a79.htm", timeout=5)
        logger.info(f"use_drission_page_login(): 跳转到登录页面，结果：{connection_result}")
        if connection_result:
            logger.info("use_drission_page_login(): 成功跳转到登录页面！")
            logger.info("use_drission_page_login(): 开始输入账号密码...")
            for character in user_account:
                # 定位到账号文本框，获取文本框元素
                page.ele("@@class=edit_lobo_cell@@name=DDDDD").input(character)
                time.sleep(random.uniform(0.05, 0.4))
            for character in user_password:
                # 定位到密码文本框，获取文本框元素
                page.ele("@@class=edit_lobo_cell@@name=upass").input(character)
                time.sleep(random.uniform(0.05, 0.4))
            # 定位到登录按钮，获取按钮元素
            ele = page.ele("@value=登录")

            logger.info("use_drission_page_login(): 开始监听网络请求...")
            page.listen.start("172.31.255.156")
            logger.info("use_drission_page_login(): 点击登录按钮...")
            # 如元素不被遮挡，用模拟点击，否则用js点击
            ele.click(by_js=None)
            time.sleep(1)

            try:
                response = page.listen.wait()
                response_body = response.response.body
                logger.info(f"use_drission_page_login(): 监听到网络请求，响应内容：{response_body}")
            except Exception as e:
                logger.error(f"use_drission_page_login(): 监听网络请求时发生异常：{str(e)}")
                colour_print(f"监听网络请求时发生异常：{str(e)}", "red")
                press_any_key_to_exit(is_auto_exit=False)
            if "Portal协议认证成功" in response_body:
                logger.info("use_drission_page_login(): Portal协议认证成功！")
                colour_print("Portal协议认证成功！", "green")
                request_url = response.url
                logger.info(f"use_drission_page_login(): 请求URL：{request_url}")
                request_headers = response.request.headers
                logger.info(f"use_drission_page_login(): 请求头：{request_headers}")
                referer = request_headers["Referer"]
                user_agent = request_headers["User-Agent"]
                headers = {"Referer": referer, "User-Agent": user_agent}
                page.quit()
                logger.info("use_drission_page_login(): 关闭浏览器。")
                return request_url, headers, user_account, user_password
            elif "账号或密码错误" in response_body or "账号错误" in response_body:
                logger.info("use_drission_page_login(): 账号或密码错误！")
                logger.info("关闭浏览器...")
                page.quit()
                logger.info("use_drission_page_login(): 提示用户重新输入账号密码...")
                colour_print("账号或密码错误！请重新输入。", "red")
                # 提示用户重新输入账号密码
                new_account = input("账号：")
                new_password = input("密码：")
                # 递归调用
                request_url, headers, correct_account, correct_password = (
                    use_drission_page_login(
                        new_account,
                        new_password,
                        retry_count=retry_count + 1,
                        max_retries=max_retries,
                    )
                )
                return request_url, headers, correct_account, correct_password
            else:
                logger.critical(f"use_drission_page_login(): 认证失败！出现意外的响应内容：{response_body}")
                colour_print(
                    f"认证失败！请检查认证系统返回信息：{response_body}", "red"
                )
                press_any_key_to_exit(is_auto_exit=False)
        else:
            logger.error("use_drission_page_login(): 无法使用浏览器打开登录页面！重试...")
            colour_print(
                f"无法使用浏览器打开登录页面，将在 {retry_delay} 秒后重试。", "yellow"
            )
            time.sleep(retry_delay)
    logger.critical("use_drission_page_login(): 无法使用浏览器打开登录页面！")
    colour_print("无法使用浏览器打开登录页面，请检查网络连接！", "red")
    press_any_key_to_exit(is_auto_exit=False)


def use_requests_login(target_url, params, headers, retry_count=0, max_retries=5):
    if retry_count >= max_retries:
        logger.error(f"use_requests_login(): 登录尝试次数过多！，重试次数：{retry_count}, 最大重试次数：{max_retries}")
        colour_print("登录尝试次数过多！", "red")
        press_any_key_to_exit(is_auto_exit=False)
        return

    if target_url is None or params is None or headers is None:
        logger.critical("use_requests_login(): 未获取到target_url、params或headers！")
        logger.critical("use_requests_login(): 请检查配置文件！")
        logger.critical("use_requests_login(): target_url: {target_url}, params: {params}, headers: {headers}")
        colour_print("未获取到目标URL、参数或请求头！程序出现错误！", "red")
        delete_config_file(config_file_name)
        press_any_key_to_exit(is_auto_exit=False)
    colour_print(
        "上次的模拟人工登录在一周之内，使用上次登录时缓存的信息尝试登录...", "cyan"
    )
    try:
        logger.info("use_requests_login(): 尝试使用requests认证...")
        logger.info(f"use_requests_login(): 请求URL：{target_url}，参数：{params}，请求头：{headers}")
        response = requests.get(url=target_url, params=params, headers=headers)
        response_text = response.text
        logger.info(f"use_requests_login(): 缓存认证返回信息：{response_text}")
    except Exception as e:
        logger.critical(f"use_requests_login(): 尝试使用缓存认证时出现错误：{str(e)}")
        colour_print(
            f"认证失败！尝试使用缓存认证时出现错误：{str(e)}！请重新运行程序。", "red"
        )
        press_any_key_to_exit(is_auto_exit=False)
    if "Portal协议认证成功" in response_text:
        logger.info("use_requests_login(): Portal协议认证成功！")
        colour_print("Portal协议认证成功！", "green")
        return params
    elif "账号或密码错误" in response_text or "账号错误" in response_text:
        logger.info("use_requests_login(): 账号或密码错误！提示用户重新输入账号密码...")
        colour_print("账号或密码错误！请重新输入。", "red")
        new_account = input("账号：")
        new_password = input("密码：")
        params["user_account"] = new_account
        params["user_password"] = new_password
        correct_params = use_requests_login(
            target_url, params, headers, retry_count + 1, max_retries
        )
        return correct_params
    else:
        logger.critical(f"use_requests_login(): 认证失败！出现意外的响应内容：{response_text}")
        colour_print(f"认证失败！请检查认证系统返回信息：{response_text}", "red")
        press_any_key_to_exit(is_auto_exit=False)


if __name__ == "__main__":
    program_name = "NJIT Quick Login"
    program_desc = "快捷登录NJIT认证系统"
    program_version = "2.5.1"
    github_url = "https://github.com/happylittle2010/NJIT_quick_login"

    config_file_name = "njit_quick_login.json"

    logger = get_logger()

    print(get_welcome_ascii_art())
    colour_print(program_name, "purple")
    colour_print(f"Version: {program_version}", "purple")
    colour_print(f"\n本程序开源于GitHub: {github_url}", "cyan")
    print("By Happylittle")
    print("\n")

    colour_print("欢迎使用NJIT快捷登录！", "cyan")
    colour_print(
        "本程序将使用您的账号密码自动登录到NJIT认证系统，以便您快速上网。", "cyan"
    )

    config, is_first_time_use = read_config_file(config_file_name)

    if is_first_time_use:
        logger.info("首次使用，未读取到配置文件。")
        if (
                not config["created_desktop_shortcut"]
                and not config["asked_desktop_shortcut_permission"]
        ):
            logger.info("首次使用，创建桌面快捷方式。")
            colour_print("\n已添加桌面快捷方式。\n", "cyan")
            add_shortcut_to_desktop(program_name, program_desc)
            config["created_desktop_shortcut"] = True
            config["asked_desktop_shortcut_permission"] = False
        save_config_file(config=config)

    check_connection_retry_delay = 5
    check_connection_max_retries = 5
    for _ in range(check_connection_max_retries):
        result = check_connection()
        if result == "Success":
            logger.info("可以正常连接网络。")
            press_any_key_to_exit(is_auto_exit=True)
        elif result == "Need authentication":
            logger.info("需要认证。")
            # 检查是否间隔了一个星期
            current_time = time.time()
            one_week = 7 * 24 * 60 * 60
            interval_time = current_time - config["last_run_drission_page_time"]
            if interval_time >= one_week:
                logger.info(f"上次使用DrissionPage的时间：{config['last_run_drission_page_time']}，间隔时间：{interval_time}")
                logger.info("距离上次使用DrissionPage已经过去一个星期。")
                request_url, headers, correct_account, correct_password = (
                    use_drission_page_login(
                        user_account=config["user_account"],
                        user_password=config["user_password"],
                    )
                )
                config["user_account"] = correct_account
                config["user_password"] = correct_password

                # use_drission_page_login返回的账号密码是经过验证、正确的，将其保存到配置文件
                target_url, correct_params = parse_request_url(
                    request_url, config["user_account"], config["user_password"]
                )
                config["target_url"] = target_url
                config["params"] = correct_params
                config["headers"] = headers
                config["last_run_drission_page_time"] = current_time

                save_config_file(config=config)
            else:
                logger.info(f"上次使用DrissionPage的时间：{config['last_run_drission_page_time']}，间隔时间：{interval_time}")
                logger.info("距离上次使用DrissionPage未满一个星期。")
                correct_params = use_requests_login(
                    config["target_url"], config["params"], config["headers"]
                )

                # use_requests_login返回的账号密码是正确的，将其保存到配置文件
                config["params"] = correct_params
                config["user_account"] = config["params"]["user_account"]
                config["user_password"] = config["params"]["user_password"]
                save_config_file(config=config)
            time.sleep(1.5)
            logger.info("认证成功，再次检查网络连接。")
            after_login_check_result = check_connection()
            if after_login_check_result == "Success":
                logger.info("认证成功，可以连接网络。")
                if (
                        not config["created_startup_shortcut"]
                        and not config["asked_startup_permission"]
                ):
                    logger.info("询问设置开机自启动。")
                    colour_print_no_new_line(
                        "\n是否要将程序设置为开机自启动？按Y、回车键或空格键确认，按其他键跳过。",
                        "yellow",
                    )
                    colour_print(
                        "（设置开机自启动可能会导致安全软件弹窗，请在弹窗后选择允许）",
                        "red",
                    )
                    user_choice = msvcrt.getch().decode()
                    if user_choice in (
                            "y",
                            "Y",
                            "\r",
                            " ",
                    ):  # '\r' 是回车键，' ' 是空格键
                        logger.info(f"用户按键：{user_choice}，设置程序为开机自启动。")
                        colour_print("已设置程序为开机自启动。\n", "cyan")
                        add_to_startup(
                            program_name=program_name, program_desc=program_desc
                        )
                        config["created_startup_shortcut"] = True
                        config["asked_startup_permission"] = True
                    else:
                        logger.info(f"用户按键：{user_choice}，跳过设置程序为开机自启动。")
                        colour_print("跳过设置程序为开机自启动。\n", "cyan")
                        config["created_startup_shortcut"] = False
                        config["asked_startup_permission"] = True
                save_config_file(config=config)
                press_any_key_to_exit(is_auto_exit=True)
            else:
                logger.error("认证成功，但仍无法连接网络，重试...")
                colour_print(f"错误：认证成功，但仍无法连接网络，将在 {check_connection_retry_delay} 秒后重试。", "red")
                time.sleep(check_connection_retry_delay)
        else:
            logger.error("无法连接网络。重试...")
            colour_print(
                f"尝试连接网络失败，将在 {check_connection_retry_delay} 秒后重试。",
                "yellow",
            )
            time.sleep(check_connection_retry_delay)
    logger.error("重试次数过多，仍无法连接网络。")
    colour_print(
        f"{check_connection_max_retries} 次重试后仍无法连接网络，请检查你的网络连接。",
        "red",
    )
    press_any_key_to_exit(is_auto_exit=False)
