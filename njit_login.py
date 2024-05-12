import getpass
import json
import msvcrt
import os
import os.path as osp
import random
import sys
import time
import winreg

import requests
import winshell
from DrissionPage import ChromiumOptions
from DrissionPage import ChromiumPage

from broswer_finder import get_browser_path
from welcome_ascii_art import get_welcome_ascii_art


def get_config_dir():
    # 获取用户目录
    user_dir = os.path.expanduser("~")

    # 检查目标目录是否存在
    config_dir = osp.join(user_dir, "happylittle", "njit_quick_login")

    # 如果目录不存在，则创建目录
    if not osp.exists(config_dir):
        os.makedirs(config_dir)

    return config_dir


def get_config_file_path(config_file_name):
    config_dir = get_config_dir()
    config_file_path: str = osp.join(config_dir, config_file_name)

    return config_file_path


def build_config(user_account, user_password, last_run_drission_page_time, target_url, params, headers, created_desktop_shortcut, asked_startup_permission, created_startup_shortcut, asked_desktop_shortcut_permission):
    return {
        "account": user_account,
        "password": user_password,
        "last_run_time": last_run_drission_page_time,
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
        is_first_time_use = False
        with open(config_file_path, "r") as f:
            config = json.load(f)
            user_account = config["account"]
            user_password = config["password"]
            last_run_drission_page_time = config["last_run_time"]
            target_url = config["target_url"]
            params = config["params"]
            headers = config["headers"]
            created_desktop_shortcut = config["created_desktop_shortcut"]
            asked_startup_permission = config["asked_startup_permission"]
            created_startup_shortcut = config["created_startup_shortcut"]
            asked_desktop_shortcut_permission = config[
                "asked_desktop_shortcut_permission"
            ]
    else:
        colour_print("首次使用，尚未保存您的账号信息，请输入账号密码：", "cyan")
        user_account = input("账号：")
        user_password = input("密码：")
        last_run_drission_page_time = 0
        target_url = None
        params = None
        headers = None
        is_first_time_use = True
        created_desktop_shortcut = False
        asked_startup_permission = False
        created_startup_shortcut = False
        asked_desktop_shortcut_permission = False

        config = build_config(
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
        )

        with open(config_file_path, "w") as f:
            json.dump(config, f)
    return (
        user_account,
        user_password,
        last_run_drission_page_time,
        target_url,
        params,
        headers,
        is_first_time_use,
        created_desktop_shortcut,
        asked_startup_permission,
        created_startup_shortcut,
        asked_desktop_shortcut_permission,
    )


def save_config_file(
        config_file_name: str,
        user_account: str,
        user_password: str,
        last_run_drission_page_time,
        target_url: str,
        params: dict,
        headers: dict,
        created_desktop_shortcut: bool,
        asked_startup_permission: bool,
        created_startup_shortcut: bool,
        asked_desktop_shortcut_permission: bool,
):
    config_file_path = get_config_file_path(config_file_name)
    if osp.exists(config_file_path):
        config = build_config(
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
        )
        with open(config_file_path, "w") as f:
            json.dump(config, f)
    else:
        colour_print("配置文件不存在，保存配置文件失败！", "red")
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
        return True
    except ImportError as err:
        colour_print(f"创建快捷方式失败！错误原因：{str(err)}", "red")
    return False


def get_desktop_path():
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    )
    return winreg.QueryValueEx(key, "Desktop")[0]


def get_startup_path():
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


def add_shortcut_to_desktop(program_name: str, program_desc: str):
    desktop_dir = get_desktop_path()
    bin_path = sys.argv[0]  # 获取自身路径
    shortcut_path = desktop_dir + f"\\{program_name}"
    create_shortcut(bin_path=bin_path, shortcut_path=shortcut_path, desc=program_desc)


def add_to_startup(program_name: str, program_desc: str):
    """
    将快捷方式添加到自启动目录
    """
    startup_path = get_startup_path()
    bin_path = sys.argv[0]  # 获取自身路径
    shortcut_path = startup_path + f"\\{program_name}"
    create_shortcut(bin_path=bin_path, shortcut_path=shortcut_path, desc=program_desc)


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
        auto_exit_timeout = 5
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
        sys.exit()
    else:
        colour_print("请按任意键退出...", "yellow")
        while True:
            if msvcrt.kbhit():
                msvcrt.getch()  # 清除输入缓冲区
                break
            else:
                time.sleep(1)  # 稍作等待，避免过度占用CPU
        sys.exit()


def check_browser_exist():
    login_page = "http://172.31.255.156/a79.htm"

    colour_print("首次运行程序，正在检查浏览器是否存在...", "cyan")
    browser_path = None
    # 尝试调用浏览器访问网页
    try:
        continue_page = ChromiumPage()
        continue_page.get(login_page)
        colour_print("浏览器检查完成。", "green")
        return continue_page
    except FileNotFoundError as e:
        # 检查e的内容是否包含“未找到浏览器”
        if "未找到浏览器" in str(e):
            # DrissionPage库没有找到浏览器，尝试使用browser_finder库查找浏览器
            chrome_path = get_browser_path("chrome")
            edge_path = get_browser_path("edge")
            # 如果chrome_path和edge_path都为None，说明没有找到浏览器
            if chrome_path is None and edge_path is None:
                colour_print(
                    "你的电脑未安装适合的浏览器，请安装Microsoft Edge浏览器或Google Chrome浏览器后重试",
                    "red",
                )
                return None
            else:
                if edge_path:
                    browser_path = edge_path
                else:
                    browser_path = chrome_path
    except Exception as e:
        colour_print(f"发生未知错误：{e}", "red")
        return None

    try:
        co = ChromiumOptions().set_browser_path(browser_path)
        continue_page = ChromiumPage(co)
        continue_page.get(login_page, timeout=10)
        return continue_page
    except FileNotFoundError as e:
        # 检查e的内容是否包含“未找到浏览器”
        if "未找到浏览器" in str(e):
            colour_print(
                "你的电脑未安装适合的浏览器，请安装Microsoft Edge浏览器或Google Chrome浏览器后重试",
                "red",
            )
            return None
    except Exception as e:
        colour_print(f"发生未知错误：{e}", "red")
        return None


def check_connection() -> str:
    colour_print("正在检查网络连接...", "cyan")
    # 网址列表
    generate_204_list = [
        "http://connect.rom.miui.com/generate_204",
        "http://connectivitycheck.platform.hicloud.com/generate_204",
        "http://wifi.vivo.com.cn/generate_204",
    ]

    for url in generate_204_list:
        try:
            response = requests.get(url, timeout=1)
            # 如果返回204状态码，联网成功
            if response.status_code == 204:
                colour_print("可以正常连接网络。", "green")
                return "Success"
        except requests.RequestException as e:
            colour_print(f"请求{url}时发生异常：{e}", "red")
            return "Failed"

    # 如果所有请求都没有返回204，检查是否需要认证
    for url in generate_204_list:
        try:
            response = requests.get(url, timeout=1)
            # 如果返回的文本包含“Authentication is required”，联网失败
            if "Authentication is required" in response.text:
                colour_print("联网失败，需要认证。", "yellow")
                return "Need authentication"
        except requests.RequestException as e:
            colour_print(f"请求{url}时发生异常：{e}", "red")
            return "Failed"
    return "Failed"


def parse_request_url(request_url: str, user_account: str, user_password: str):
    from urllib.parse import urlparse, parse_qs

    # 解析URL
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
    return target_url, params


def use_drission_page_login(
        user_account: str,
        user_password: str,
        chromium_page: ChromiumPage = None,
        retry_count=0,
        max_retries=5,
):
    if retry_count >= max_retries:
        colour_print("登录尝试次数过多！", "red")
        press_any_key_to_exit(is_auto_exit=False)
        return

    colour_print("正在模拟人工操作浏览器登录认证系统...", "cyan")

    if chromium_page is None:
        page = ChromiumPage()
    else:
        page = chromium_page

    retry_delay = 5
    page_get_max_retries = 5
    for _ in range(page_get_max_retries):
        # 跳转到登录页面
        connection_result = page.get("http://172.31.255.156/a79.htm", timeout=5)
        if connection_result:
            page.listen.start("172.31.255.156")
            for character in user_account:
                # 定位到账号文本框，获取文本框元素
                page.ele("@@class=edit_lobo_cell@@name=DDDDD").input(character)
                time.sleep(random.uniform(0.1, 0.3))
            for character in user_password:
                # 定位到密码文本框，获取文本框元素
                page.ele("@@class=edit_lobo_cell@@name=upass").input(character)
                time.sleep(random.uniform(0.1, 0.3))
            # 定位到登录按钮，获取按钮元素
            time.sleep(1)
            ele = page.ele("@value=登录")

            # 如元素不被遮挡，用模拟点击，否则用js点击
            ele.click(by_js=None)

            response = page.listen.wait()
            time.sleep(1)
            response_body = response.response.body
            if "Portal协议认证成功" in response_body:
                colour_print("Portal协议认证成功！", "green")
                request_url = response.url
                request_headers = response.request.headers
                referer = request_headers["Referer"]
                user_agent = request_headers["User-Agent"]
                headers = {"Referer": referer, "User-Agent": user_agent}
                page.quit()
                return request_url, headers, user_account, user_password
            elif "账号或密码错误" in response_body or "账号错误" in response_body:
                page.quit()
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
                colour_print(
                    f"认证失败！请检查认证系统返回信息：{response_body}", "red"
                )
                press_any_key_to_exit(is_auto_exit=False)
        else:
            colour_print(
                f"无法使用浏览器打开登录页面，将在 {retry_delay} 秒后重试。", "yellow"
            )
            time.sleep(retry_delay)
    colour_print("无法使用浏览器打开登录页面，请检查网络连接！", "red")
    press_any_key_to_exit(is_auto_exit=False)


def use_requests_login(target_url, params, headers, retry_count=0, max_retries=5):
    if retry_count >= max_retries:
        colour_print("登录尝试次数过多！", "red")
        press_any_key_to_exit(is_auto_exit=False)
        return

    if target_url is None or params is None or headers is None:
        colour_print("程序出现错误，请重新运行程序！", "red")
        os.remove(config_file_name)
        press_any_key_to_exit(is_auto_exit=False)
    colour_print(
        "上次的模拟人工登录在一周之内，使用上次登录时缓存的信息尝试登录...", "cyan"
    )
    try:
        response = requests.get(target_url, params=params, headers=headers)
        response_text = response.text
    except Exception as e:
        colour_print(
            f"认证失败！尝试使用缓存认证时出现错误：{str(e)}！请重新运行程序。", "red"
        )
        os.remove(config_file_name)
        press_any_key_to_exit(is_auto_exit=False)
    if "Portal协议认证成功" in response_text:
        colour_print("Portal协议认证成功！", "green")
        return params
    elif "账号或密码错误" in response_text or "账号错误" in response_text:
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
        colour_print(f"认证失败！请检查认证系统返回信息：{response_text}", "red")
        press_any_key_to_exit(is_auto_exit=False)


if __name__ == "__main__":
    program_name = "NJIT Quick Login"
    program_desc = "快捷登录NJIT认证系统"
    program_version = "2.3.1"
    github_url = "https://github.com/happylittle2010/NJIT_quick_login"

    config_file_name = "njit_quick_login.json"

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

    (
        user_account,
        user_password,
        last_run_drission_page_time,
        target_url,
        params,
        headers,
        is_first_time_use,
        created_desktop_shortcut,
        asked_startup_permission,
        created_startup_shortcut,
        asked_desktop_shortcut_permission,
    ) = read_config_file(config_file_name)

    if is_first_time_use:
        if not created_desktop_shortcut and not asked_desktop_shortcut_permission:
            colour_print("\n已添加桌面快捷方式。\n", "cyan")
            add_shortcut_to_desktop(program_name, program_desc)
            created_desktop_shortcut = True
            asked_desktop_shortcut_permission = False
        save_config_file(
            config_file_name=config_file_name,
            user_account=user_account,
            user_password=user_password,
            last_run_drission_page_time=last_run_drission_page_time,
            target_url=target_url,
            params=params,
            headers=headers,
            created_desktop_shortcut=created_desktop_shortcut,
            asked_desktop_shortcut_permission=asked_desktop_shortcut_permission,
            created_startup_shortcut=created_startup_shortcut,
            asked_startup_permission=asked_startup_permission,
        )

        continue_page = check_browser_exist()
        if continue_page is None:
            press_any_key_to_exit(is_auto_exit=False)

    check_connection_retry_delay = 5
    check_connection_max_retries = 5
    for retry in range(check_connection_max_retries):
        result = check_connection()
        if result == "Success":
            if is_first_time_use:
                continue_page.quit()
            press_any_key_to_exit(is_auto_exit=True)
        elif result == "Need authentication":
            # 检查是否间隔了一个星期
            current_time = time.time()
            one_week = 7 * 24 * 60 * 60
            if current_time - last_run_drission_page_time >= one_week:
                if is_first_time_use:
                    request_url, headers, correct_account, correct_password = (
                        use_drission_page_login(
                            user_account, user_password, continue_page
                        )
                    )
                else:
                    request_url, headers, correct_account, correct_password = (
                        use_drission_page_login(user_account, user_password)
                    )

                # use_drission_page_login返回的账号密码是正确的，将其保存到配置文件
                target_url, correct_params = parse_request_url(
                    request_url, correct_account, correct_password
                )
                last_run_drission_page_time = current_time

                save_config_file(
                    config_file_name=config_file_name,
                    user_account=user_account,
                    user_password=user_password,
                    last_run_drission_page_time=last_run_drission_page_time,
                    target_url=target_url,
                    params=params,
                    headers=headers,
                    created_desktop_shortcut=created_desktop_shortcut,
                    asked_desktop_shortcut_permission=asked_desktop_shortcut_permission,
                    created_startup_shortcut=created_startup_shortcut,
                    asked_startup_permission=asked_startup_permission,
                )
            else:
                correct_params = use_requests_login(target_url, params, headers)

                # use_requests_login返回的账号密码是正确的，将其保存到配置文件
                correct_account = correct_params["user_account"]
                correct_password = correct_params["user_password"]
                save_config_file(
                    config_file_name=config_file_name,
                    user_account=user_account,
                    user_password=user_password,
                    last_run_drission_page_time=last_run_drission_page_time,
                    target_url=target_url,
                    params=params,
                    headers=headers,
                    created_desktop_shortcut=created_desktop_shortcut,
                    asked_desktop_shortcut_permission=asked_desktop_shortcut_permission,
                    created_startup_shortcut=created_startup_shortcut,
                    asked_startup_permission=asked_startup_permission,
                )
            time.sleep(3)
            after_login_check_result = check_connection()
            if after_login_check_result == "Success":
                if not created_startup_shortcut and not asked_startup_permission:
                    colour_print_no_new_line(
                        "\n是否要将程序设置为开机自启动？按Y、回车键或空格键确认，按其他键跳过。",
                        "yellow",
                    )
                    colour_print("（设置开机自启动可能会导致安全软件弹窗，请在弹窗后选择允许）", "red")
                    user_choice = msvcrt.getch().decode()
                    if user_choice in ('y', 'Y', '\r', ' '):  # '\r' 是回车键，' ' 是空格键
                        colour_print("已设置程序为开机自启动。\n", "cyan")
                        add_to_startup(program_name, program_desc)
                        created_startup_shortcut = True
                        asked_startup_permission = True
                    else:
                        colour_print("跳过设置程序为开机自启动。\n", "cyan")
                        created_startup_shortcut = False
                        asked_startup_permission = True
                save_config_file(
                    config_file_name=config_file_name,
                    user_account=user_account,
                    user_password=user_password,
                    last_run_drission_page_time=last_run_drission_page_time,
                    target_url=target_url,
                    params=params,
                    headers=headers,
                    created_desktop_shortcut=created_desktop_shortcut,
                    asked_desktop_shortcut_permission=asked_desktop_shortcut_permission,
                    created_startup_shortcut=created_startup_shortcut,
                    asked_startup_permission=asked_startup_permission,
                )
                press_any_key_to_exit(is_auto_exit=True)
            else:
                colour_print("错误：认证成功，但仍无法连接网络。", "red")
                os.remove(config_file_name)
                press_any_key_to_exit(is_auto_exit=False)
        else:
            colour_print(
                f"尝试连接网络失败，将在 {check_connection_retry_delay} 秒后重试。",
                "yellow",
            )
            time.sleep(check_connection_retry_delay)
    colour_print(
        f"{check_connection_max_retries} 次重试后仍无法连接网络，请检查你的网络连接。",
        "red",
    )
    press_any_key_to_exit(is_auto_exit=False)