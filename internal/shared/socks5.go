package shared

import (
	"errors"
	"strings"
	"unicode"
)

func ValidateSOCKS5Credentials(username, password string) error {
	if len(username) < 1 || len(username) > 255 || strings.ContainsAny(username, ":,=\"\\") || strings.IndexFunc(username, unicode.IsSpace) >= 0 || strings.IndexFunc(username, unicode.IsControl) >= 0 {
		return errors.New("SOCKS5 用户名须为 1–255 字节，不能含空白、控制字符或 : , = 引号和反斜线")
	}
	if len(password) < 8 || len(password) > 255 || strings.ContainsAny(password, ",\"\\") || strings.IndexFunc(password, unicode.IsSpace) >= 0 || strings.IndexFunc(password, unicode.IsControl) >= 0 {
		return errors.New("SOCKS5 密码须为 8–255 字节，不能含空白、控制字符、逗号、引号或反斜线")
	}
	return nil
}

func ValidateAgentProxy(p *SOCKS5Proxy) error {
	if p == nil {
		return nil
	}
	if p.Host == "" && p.Port == 0 && p.Username == "" && p.Password == "" {
		return nil
	}
	if err := ValidateForwardTarget(ForwardTarget{Host: p.Host, Port: p.Port}); err != nil {
		return err
	}
	return ValidateSOCKS5Credentials(p.Username, p.Password)
}
