from __future__ import annotations

import base64
import html
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


@dataclass
class OAuthPasswordResult:
    success: bool
    refresh_token: str = ""
    error: str = ""


class LoginFormParser(HTMLParser):
    """Extract form actions and input values from Microsoft login pages."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: List[Dict[str, object]] = []
        self._current_form: Optional[Dict[str, object]] = None
        self.inputs: Dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr_map = {key: value or "" for key, value in attrs}
        if tag.lower() == "form":
            self._current_form = {
                "action": attr_map.get("action", ""),
                "inputs": {},
            }
            self.forms.append(self._current_form)
            return

        if tag.lower() != "input":
            return

        name = attr_map.get("name")
        if not name:
            return
        value = attr_map.get("value", "")
        self.inputs[name] = value
        if self._current_form is not None:
            form_inputs = self._current_form.setdefault("inputs", {})
            if isinstance(form_inputs, dict):
                form_inputs[name] = value

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current_form = None

    def first_form_action(self) -> str:
        for form in self.forms:
            action = str(form.get("action") or "").strip()
            if action:
                return action
        return ""

    def first_form_inputs(self) -> Dict[str, str]:
        for form in self.forms:
            inputs = form.get("inputs")
            if isinstance(inputs, dict) and inputs:
                return {str(key): str(value) for key, value in inputs.items()}
        return dict(self.inputs)

    def best_login_form(self) -> Tuple[Dict[str, str], str]:
        preferred_names = {"flowToken", "PPFT", "login", "loginfmt", "passwd"}
        for form in self.forms:
            inputs = form.get("inputs")
            if not isinstance(inputs, dict):
                continue
            if preferred_names.intersection(str(key) for key in inputs):
                return (
                    {str(key): str(value) for key, value in inputs.items()},
                    str(form.get("action") or "").strip(),
                )
        return self.first_form_inputs(), self.first_form_action()


def decode_javascript_string(value: str) -> str:
    text = html.unescape(str(value or ""))

    def replace_unicode(match: re.Match[str]) -> str:
        return chr(int(match.group(1), 16))

    def replace_hex(match: re.Match[str]) -> str:
        return chr(int(match.group(1), 16))

    text = re.sub(r"\\u([0-9a-fA-F]{4})", replace_unicode, text)
    text = re.sub(r"\\x([0-9a-fA-F]{2})", replace_hex, text)
    replacements = {
        r"\/": "/",
        r"\"": '"',
        r"\'": "'",
        r"\&": "&",
    }
    for escaped, plain in replacements.items():
        text = text.replace(escaped, plain)
    return text


def extract_javascript_string(html_text: str, key: str) -> str:
    key_pattern = re.escape(key)
    patterns = [
        rf'"{key_pattern}"\s*:\s*"((?:\\.|[^"\\])*)"',
        rf"'{key_pattern}'\s*:\s*'((?:\\.|[^'\\])*)'",
        rf"{key_pattern}\s*:\s*\"((?:\\.|[^\"\\])*)\"",
        rf"{key_pattern}\s*:\s*'((?:\\.|[^'\\])*)'",
    ]
    for pattern in patterns:
        match = re.search(pattern, html_text or "", flags=re.IGNORECASE | re.DOTALL)
        if match:
            return decode_javascript_string(match.group(1))
    return ""


def extract_login_config(html_text: str) -> Dict[str, object]:
    decoder = json.JSONDecoder()
    for pattern in (r"\$Config\s*=\s*", r"\bConfig\s*=\s*"):
        for match in re.finditer(pattern, html_text or "", flags=re.IGNORECASE):
            try:
                payload, _ = decoder.raw_decode((html_text or "")[match.end():])
            except ValueError:
                continue
            if isinstance(payload, dict):
                return payload
    return {}


def get_config_string(config: Dict[str, object], key: str) -> str:
    value = config.get(key)
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return ""
    return str(value)


def extract_login_config_inputs(html_text: str) -> Dict[str, str]:
    inputs: Dict[str, str] = {}
    config = extract_login_config(html_text)
    post_params = config.get("oPostParams")
    if isinstance(post_params, dict):
        for key, value in post_params.items():
            if value is not None and not isinstance(value, (dict, list)):
                inputs[str(key)] = str(value)

    sft_tag = get_config_string(config, "sFTTag") or extract_javascript_string(html_text, "sFTTag")
    if sft_tag:
        nested_parser = LoginFormParser()
        nested_parser.feed(sft_tag)
        inputs.update(nested_parser.inputs)

    flow_token = get_config_string(config, "sFT") or extract_javascript_string(html_text, "sFT")
    flow_token_name = get_config_string(config, "sFTName") or extract_javascript_string(html_text, "sFTName") or "flowToken"
    if flow_token and flow_token_name:
        inputs.setdefault(flow_token_name, flow_token)
        if flow_token_name == "flowToken":
            inputs.setdefault("flowToken", flow_token)

    for js_key, input_name in (
        ("flowToken", "flowToken"),
        ("PPFT", "PPFT"),
        ("ctx", "ctx"),
        ("sCtx", "ctx"),
        ("canary", "canary"),
        ("apiCanary", "apiCanary"),
        ("hpgrequestid", "hpgrequestid"),
        ("i13", "i13"),
        ("login", "login"),
        ("loginfmt", "loginfmt"),
        ("type", "type"),
        ("LoginOptions", "LoginOptions"),
        ("lrt", "lrt"),
        ("lrtPartition", "lrtPartition"),
        ("hisRegion", "hisRegion"),
        ("hisScaleUnit", "hisScaleUnit"),
        ("passwd", "passwd"),
        ("ps", "ps"),
        ("PPSX", "PPSX"),
        ("NewUser", "NewUser"),
        ("FoundMSAs", "FoundMSAs"),
        ("fspost", "fspost"),
        ("i21", "i21"),
        ("CookieDisclosure", "CookieDisclosure"),
        ("IsFidoSupported", "IsFidoSupported"),
        ("isSignupPost", "isSignupPost"),
        ("i19", "i19"),
    ):
        value = get_config_string(config, js_key) or extract_javascript_string(html_text, js_key)
        if value:
            inputs.setdefault(input_name, value)

    return inputs


def extract_login_config_action(html_text: str) -> str:
    config = extract_login_config(html_text)
    for key in ("urlPost", "urlPostAad", "urlPostMsa"):
        action = get_config_string(config, key) or extract_javascript_string(html_text, key)
        if action:
            return action
    return ""


def extract_html_redirect_url(html_text: str) -> str:
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html_text or "", flags=re.IGNORECASE | re.DOTALL)
    title = html.unescape(re.sub(r"\s+", " ", title_match.group(1))).strip().lower() if title_match else ""
    is_redirect_page = "redirect" in title or "重定向" in title

    if is_redirect_page:
        content_match = re.search(
            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']([^"\']+)["\']',
            html_text or "",
            flags=re.IGNORECASE | re.DOTALL,
        )
        if content_match:
            content = html.unescape(content_match.group(1))
            url_match = re.search(r"url\s*=\s*([^;]+)$", content, flags=re.IGNORECASE)
            if url_match:
                redirect_url = decode_javascript_string(url_match.group(1).strip(" '\""))
                if "/jsdisabled" not in redirect_url.lower():
                    return redirect_url

    for pattern in (
        r"window\.location\.(?:href|assign)\s*=\s*['\"]((?:\\.|[^'\"\\])+)['\"]",
        r"window\.location\.(?:assign|replace)\(\s*['\"]((?:\\.|[^'\"\\])+)['\"]\s*\)",
        r"document\.location\s*=\s*['\"]((?:\\.|[^'\"\\])+)['\"]",
    ):
        match = re.search(pattern, html_text or "", flags=re.IGNORECASE | re.DOTALL)
        if match:
            return decode_javascript_string(match.group(1))

    if is_redirect_page:
        return extract_login_config_action(html_text)

    return ""


def extract_meta_content(html_text: str, name: str) -> str:
    name_pattern = re.escape(name)
    match = re.search(
        rf'<meta[^>]+name=["\']{name_pattern}["\'][^>]+content=["\']([^"\']*)["\']',
        html_text or "",
        flags=re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return ""
    return html.unescape(match.group(1)).strip()


def extract_page_title(html_text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html_text or "", flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return html.unescape(re.sub(r"\s+", " ", match.group(1))).strip()


def is_login_auto_post_interstitial(html_text: str) -> bool:
    page_id = extract_meta_content(html_text, "PageID").lower()
    if page_id in {"bssointerrupt"}:
        return True

    has_post_params = "oPostParams" in (html_text or "")
    has_action = bool(extract_login_config_action(html_text))
    has_flow_token = bool(extract_javascript_string(html_text, "flowToken"))
    return has_post_params and has_action and has_flow_token and "ConvergedSignIn" not in (html_text or "")


def extract_microsoft_error(html_text: str) -> str:
    config = extract_login_config(html_text)
    service_message = get_config_string(config, "strServiceExceptionMessage") or extract_javascript_string(html_text, "strServiceExceptionMessage")
    main_message = get_config_string(config, "strMainMessage") or extract_javascript_string(html_text, "strMainMessage")
    additional_message = get_config_string(config, "strAdditionalMessage") or extract_javascript_string(html_text, "strAdditionalMessage")
    error_code = get_config_string(config, "iErrorCode") or extract_javascript_string(html_text, "iErrorCode")

    parts = [part for part in (service_message, main_message, additional_message) if part]
    if not parts and error_code:
        parts.append(f"Microsoft 登录错误代码 {error_code}")
    return "；".join(parts)


def classify_microsoft_login_page(html_text: str) -> str:
    microsoft_error = extract_microsoft_error(html_text)
    if microsoft_error:
        return f"Microsoft 登录错误: {microsoft_error}"

    page_id = extract_meta_content(html_text, "PageID")
    page_id_lower = page_id.lower()
    title = extract_page_title(html_text)
    text_lower = (html_text or "").lower()

    if "captcha" in text_lower or "hip" in page_id_lower:
        return "Microsoft 要求验证码，需手动处理"

    verification_markers = (
        "proof",
        "otc",
        "tfa",
        "mfa",
        "challenge",
        "identity",
        "risk",
        "recover",
        "verify",
        "authenticator",
    )
    if any(marker in page_id_lower for marker in verification_markers):
        return f"Microsoft 要求额外安全验证，需手动处理{f'（{page_id}）' if page_id else ''}"

    if "ConvergedSignIn".lower() == page_id_lower and extract_login_config_action(html_text):
        return "提交密码后仍停留在 Microsoft 登录页，可能密码错误、账号受限或需要额外验证"

    if page_id:
        return f"未获取到授权 code，停留在 Microsoft 页面: {page_id}"
    if title:
        return f"未获取到授权 code，停留在 Microsoft 页面: {title}"
    return ""


def parse_login_form(html: str) -> Tuple[Dict[str, str], str]:
    parser = LoginFormParser()
    parser.feed(html or "")
    inputs, action = parser.best_login_form()

    config_inputs = extract_login_config_inputs(html)
    for key, value in config_inputs.items():
        inputs.setdefault(key, value)

    if not action:
        action = extract_login_config_action(html)
    return inputs, action


def build_pkce_pair() -> Tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    return verifier, challenge


def is_redirect_match(location: str, redirect_uri: str) -> bool:
    parsed_location = urlparse(location)
    parsed_redirect = urlparse(redirect_uri)
    return (
        parsed_location.scheme == parsed_redirect.scheme
        and parsed_location.netloc == parsed_redirect.netloc
        and parsed_location.path.rstrip("/") == parsed_redirect.path.rstrip("/")
    )


def extract_authorization_code(location: str, redirect_uri: str, expected_state: str) -> Tuple[bool, str]:
    if not location or not is_redirect_match(location, redirect_uri):
        return False, ""

    query = parse_qs(urlparse(location).query)
    error = query.get("error", [""])[0]
    if error:
        description = query.get("error_description", [""])[0]
        return False, f"{error}: {description}".strip(": ")

    state = query.get("state", [""])[0]
    if expected_state and state != expected_state:
        return False, "OAuth state 校验失败"

    code = query.get("code", [""])[0]
    if not code:
        return False, "授权回调中没有 code"
    return True, code


def normalize_proxy_url(proxy_url: str) -> str:
    value = str(proxy_url or "").strip()
    if value.lower() in {"direct", "none", "no_proxy", "noproxy", "直连"}:
        return ""
    return value


class OutlookPasswordOAuthClient:
    AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    LOGIN_URL = "https://login.microsoftonline.com"

    def __init__(
        self,
        client_id: str,
        redirect_uri: str,
        scopes: Iterable[str],
        *,
        proxy_url: str = "",
        timeout: int = 60,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scopes = [scope for scope in scopes if str(scope or "").strip()]
        self.proxy_url = normalize_proxy_url(proxy_url)
        self.timeout = timeout
        self.session = session or requests.Session()
        self.code_verifier = ""
        self.code_challenge = ""
        self.state = ""

        if self.proxy_url:
            self.session.proxies = {
                "http": self.proxy_url,
                "https": self.proxy_url,
            }
        self.session.headers.update({
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })

    def build_authorization_url(self) -> str:
        self.code_verifier, self.code_challenge = build_pkce_pair()
        self.state = secrets.token_urlsafe(16)
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "response_mode": "query",
            "scope": " ".join(self.scopes),
            "code_challenge": self.code_challenge,
            "code_challenge_method": "S256",
            "state": self.state,
        }
        return f"{self.AUTH_URL}?{urlencode(params)}"

    def _absolute_action_url(self, action_url: str) -> str:
        return urljoin(self.LOGIN_URL, str(action_url or "").strip())

    def _follow_html_redirects(self, response: requests.Response) -> requests.Response:
        current_response = response
        for _ in range(5):
            redirect_url = extract_html_redirect_url(current_response.text)
            if not redirect_url:
                return current_response

            absolute_url = urljoin(current_response.url, redirect_url)
            if absolute_url == current_response.url:
                return current_response

            current_response = self.session.get(
                absolute_url,
                timeout=self.timeout,
                allow_redirects=True,
            )
        return current_response

    def _follow_login_interstitials(self, response: requests.Response, email_addr: str) -> requests.Response:
        current_response = response
        for _ in range(4):
            if not is_login_auto_post_interstitial(current_response.text):
                followed_response = self._follow_html_redirects(current_response)
                if followed_response is current_response:
                    return current_response
                current_response = followed_response
                continue

            interstitial_inputs, interstitial_action = parse_login_form(current_response.text)
            if (
                (not interstitial_inputs.get("flowToken") and not interstitial_inputs.get("PPFT"))
                or not interstitial_action
            ):
                return current_response

            interstitial_payload = self._build_login_payload(email_addr, "", interstitial_inputs)
            current_response = self.session.post(
                self._absolute_action_url(interstitial_action),
                data=interstitial_payload,
                timeout=self.timeout,
                allow_redirects=False,
            )
            if current_response.status_code in (301, 302, 303, 307, 308):
                location = current_response.headers.get("Location", "")
                if location:
                    absolute_location = urljoin(current_response.url, location)
                    current_response = self.session.post(
                        absolute_location,
                        data=interstitial_payload,
                        timeout=self.timeout,
                        allow_redirects=False,
                    )
            current_response = self._follow_html_redirects(current_response)

        return current_response

    def _build_login_payload(self, email_addr: str, password: str, form_inputs: Dict[str, str]) -> Dict[str, str]:
        payload = dict(form_inputs or {})
        payload.update({
            "i13": payload.get("i13", "0"),
            "login": email_addr,
            "loginfmt": email_addr,
            "type": payload.get("type", "11"),
            "LoginOptions": payload.get("LoginOptions", "3"),
            "lrt": payload.get("lrt", ""),
            "lrtPartition": payload.get("lrtPartition", ""),
            "hisRegion": payload.get("hisRegion", ""),
            "hisScaleUnit": payload.get("hisScaleUnit", ""),
            "passwd": password,
            "ps": payload.get("ps", "2"),
            "PPSX": payload.get("PPSX", ""),
            "NewUser": payload.get("NewUser", "1"),
            "FoundMSAs": payload.get("FoundMSAs", ""),
            "fspost": payload.get("fspost", "0"),
            "i21": payload.get("i21", "0"),
            "CookieDisclosure": payload.get("CookieDisclosure", "0"),
            "IsFidoSupported": payload.get("IsFidoSupported", "1"),
            "isSignupPost": payload.get("isSignupPost", "0"),
            "i19": payload.get("i19", "12345"),
        })
        return payload

    def _extract_code_from_redirects(self, response: requests.Response) -> Tuple[bool, str]:
        current_response = response
        for _ in range(12):
            location = current_response.headers.get("Location", "")
            if current_response.status_code in (301, 302, 303, 307, 308) and location:
                absolute_location = urljoin(current_response.url, location)
                code_success, code_or_error = extract_authorization_code(
                    absolute_location,
                    self.redirect_uri,
                    self.state,
                )
                if code_success or is_redirect_match(absolute_location, self.redirect_uri):
                    return code_success, code_or_error

                current_response = self.session.get(
                    absolute_location,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                continue

            code_success, code_or_error = extract_authorization_code(
                current_response.url,
                self.redirect_uri,
                self.state,
            )
            if code_success or is_redirect_match(current_response.url, self.redirect_uri):
                return code_success, code_or_error

            html_redirect_url = extract_html_redirect_url(current_response.text)
            if html_redirect_url:
                current_response = self.session.get(
                    urljoin(current_response.url, html_redirect_url),
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                continue

            page_message = classify_microsoft_login_page(current_response.text)
            if page_message:
                return False, page_message
            break

        return False, "未获取到授权 code，可能需要验证码、二次验证或账号密码无效"

    def login_for_code(self, email_addr: str, password: str) -> Tuple[bool, str]:
        auth_response = self.session.get(
            self.build_authorization_url(),
            timeout=self.timeout,
            allow_redirects=True,
        )
        if auth_response.status_code != 200:
            return False, f"访问授权页失败: HTTP {auth_response.status_code}"
        auth_response = self._follow_html_redirects(auth_response)

        form_inputs, post_action = parse_login_form(auth_response.text)
        if not form_inputs.get("flowToken") and not form_inputs.get("PPFT"):
            return False, "授权页缺少登录表单 token"
        if not post_action:
            return False, "授权页缺少登录表单地址"

        email_payload = self._build_login_payload(email_addr, "", form_inputs)
        email_response = self.session.post(
            self._absolute_action_url(post_action),
            data=email_payload,
            timeout=self.timeout,
            allow_redirects=True,
        )
        if email_response.status_code != 200:
            return False, f"提交邮箱失败: HTTP {email_response.status_code}"
        email_response = self._follow_login_interstitials(email_response, email_addr)

        password_inputs, password_action = parse_login_form(email_response.text)
        if not password_inputs.get("flowToken") and not password_inputs.get("PPFT"):
            microsoft_error = extract_microsoft_error(email_response.text)
            if microsoft_error:
                return False, f"密码页返回 Microsoft 错误: {microsoft_error}"
            return False, "密码页缺少登录表单 token"
        if not password_action:
            microsoft_error = extract_microsoft_error(email_response.text)
            if microsoft_error:
                return False, f"密码页返回 Microsoft 错误: {microsoft_error}"
            return False, "密码页缺少登录表单地址"

        password_payload = self._build_login_payload(email_addr, password, password_inputs)
        password_response = self.session.post(
            self._absolute_action_url(password_action),
            data=password_payload,
            timeout=self.timeout,
            allow_redirects=False,
        )
        return self._extract_code_from_redirects(password_response)

    def exchange_token(self, code: str) -> OAuthPasswordResult:
        token_payload = {
            "client_id": self.client_id,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
            "code_verifier": self.code_verifier,
            "scope": " ".join(self.scopes),
        }
        response = self.session.post(
            self.TOKEN_URL,
            data=token_payload,
            timeout=self.timeout,
        )
        if response.status_code != 200:
            error = ""
            try:
                payload = response.json()
                error = payload.get("error_description") or payload.get("error") or ""
            except ValueError:
                error = response.text[:500]
            return OAuthPasswordResult(False, error=f"换取 token 失败: HTTP {response.status_code} {error}".strip())

        payload = response.json()
        refresh_token = str(payload.get("refresh_token") or "").strip()
        if not refresh_token:
            return OAuthPasswordResult(False, error="Token 响应中没有 refresh_token")
        return OAuthPasswordResult(True, refresh_token=refresh_token)

    def get_refresh_token(self, email_addr: str, password: str) -> OAuthPasswordResult:
        try:
            code_success, code_or_error = self.login_for_code(email_addr, password)
            if not code_success:
                return OAuthPasswordResult(False, error=code_or_error)
            return self.exchange_token(code_or_error)
        except requests.RequestException as exc:
            return OAuthPasswordResult(False, error=f"网络请求失败: {exc}")
        except Exception as exc:
            return OAuthPasswordResult(False, error=str(exc))
