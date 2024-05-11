"""
使用 get_browser_path 函数可获取对应名称的浏览器的安装位置，使用 open_url 函数可直接使用指定的浏览器打开对应页面，
可同时指定多个浏览器，优先级从前到后。当前支持 'IE'，'chrome'，'edge'，'firefox'，'360' 等浏览器，如果有其他浏览器需要支持，只需在 _browser_regs 中补充对应注册表信息即可
"""

import webbrowser
import winreg

# 浏览器注册表信息
_browser_regs = {
    "chrome": r"SOFTWARE\Clients\StartMenuInternet\Google Chrome\DefaultIcon",
    "edge": r"SOFTWARE\Clients\StartMenuInternet\Microsoft Edge\DefaultIcon",
    "360": r"SOFTWARE\Clients\StartMenuInternet\360Chrome\DefaultIcon",
}


def get_browser_path(browser):
    """
    获取浏览器的安装路径

    :param browser: 浏览器名称
    """
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _browser_regs[browser])
    except FileNotFoundError:
        return None
    value, _type = winreg.QueryValueEx(key, "")
    return value.split(",")[0]


def open_url(url, browsers=("IE",)):
    """
    使用指定的浏览器打开url对应的网页地址

    :param url: 网页地址
    :param browsers: 浏览器名称列表
    :return: 是否打开成功
    """
    for browser in browsers:
        path = get_browser_path(browser)
        if path:
            print(f"open with browser: `{browser}`, path: `{path}`")
        webbrowser.register(browser, None, webbrowser.BackgroundBrowser(path))
        webbrowser.get(browser).open(url)
        return True
    return False


if __name__ == "__main__":
    print("谷歌:", get_browser_path("chrome"))
    print("360: ", get_browser_path("360"))
    print("edge: ", get_browser_path("edge"))
    #
    # if open_url('www.baidu.com', browsers=('chrome', 'firefox')):
    #     print('打开成功')
    # else:
    #     print('打开失败，请安装 Chrome 或 Firefox 浏览器后重试')
