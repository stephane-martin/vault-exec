package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"unicode"

	"github.com/hashicorp/vault/api"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	app := cli.NewApp()
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "address,vault-addr",
			Value:  "http://127.0.0.1:8200",
			EnvVar: "VAULT_ADDR",
			Usage:  "The address of the Vault server",
		},
		cli.StringFlag{
			Name:   "token",
			Value:  "",
			EnvVar: "VAULT_TOKEN",
			Usage:  "Vault authentication token, when using the token auth method",
		},
		cli.StringSliceFlag{
			Name:  "secret",
			Usage: "path of secret to be read from Vault",
		},
		cli.StringFlag{
			Name:   "method",
			Usage:  "type of authentication to use such as 'userpass' or 'ldap'",
			Value:  "token",
			EnvVar: "VAULT_AUTH_METHOD",
		},
		cli.StringFlag{
			Name:   "path",
			Usage:  "remote path in Vault where the auth method is enabled",
			Value:  "",
			EnvVar: "VAULT_AUTH_PATH",
		},
		cli.StringFlag{
			Name:   "username",
			Usage:  "Vault username, when using the userpass auth method",
			Value:  "",
			EnvVar: "VAULT_USERNAME",
		},
		cli.StringFlag{
			Name:   "password",
			Usage:  "Vault password, whe, using the userpass auth method",
			Value:  "",
			EnvVar: "VAULT_PASSWORD",
		},
		cli.StringFlag{
			Name:   "role-id",
			Usage:  "RoleID, when using the approle auth method",
			Value:  "",
			EnvVar: "VAULT_ROLE_ID",
		},
		cli.StringFlag{
			Name:   "secret-id",
			Usage:  "SecretID, when using the approle auth method",
			Value:  "",
			EnvVar: "VAULT_SECRET_ID",
		},
		cli.BoolFlag{
			Name:   "upcase",
			Usage:  "convert all environment variable keys to uppercase",
			EnvVar: "UPCASE",
		},
		cli.BoolFlag{
			// TODO
			Name:   "prefix",
			Usage:  "prefix the environment variable keys with the name of secret",
			EnvVar: "PREFIX",
		},
		cli.StringFlag{
			Name:  "forward",
			Usage: "comma separated list of environment variable keys to forward from parent environment",
			Value: "*",
		},
	}
	app.Action = func(c *cli.Context) error {
		secrets := c.GlobalStringSlice("secret")
		authType := strings.ToLower(c.GlobalString("method"))
		path := strings.TrimSpace(c.GlobalString("path"))
		if path == "" {
			path = authType
		}
		args := c.Args()
		if len(args) == 0 {
			args = []string{"env"}
		}
		config := api.DefaultConfig()
		config.Address = c.GlobalString("address")
		client, err := api.NewClient(config)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("error creating vault client: %s", err), 1)
		}
		switch authType {
		case "token":
			tok := strings.TrimSpace(c.GlobalString("token"))
			if tok == "" {
				t, err := input("enter token: ", true)
				if err != nil {
					return cli.NewExitError(fmt.Sprintf("error reading token: %s", err), 1)
				}
				if t == "" {
					return cli.NewExitError("empty token", 1)
				}
				tok = t
			}
			client.SetToken(tok)

		case "ldap":
			// TODO

		case "userpass":
			username := strings.TrimSpace(c.GlobalString("username"))
			password := strings.TrimSpace(c.GlobalString("password"))
			if username == "" {
				u, err := input("enter username: ", false)
				if err != nil {
					return cli.NewExitError(fmt.Sprintf("error reading username: %s", err), 1)
				}
				if u == "" {
					return cli.NewExitError("empty username", 1)
				}
				username = u
			}
			if password == "" {
				p, err := input("enter password: ", true)
				if err != nil {
					return cli.NewExitError(fmt.Sprintf("error reading password: %s", err), 1)
				}
				if p == "" {
					return cli.NewExitError("empty password", 1)
				}
				password = p
			}
			path = fmt.Sprintf("auth/%s/login/%s", path, username)
			options := map[string]interface{}{
				"password": password,
			}
			secret, err := client.Logical().Write(path, options)
			if err != nil {
				return cli.NewExitError(fmt.Sprintf("vault auth error: %s", err), 1)
			}
			client.SetToken(secret.Auth.ClientToken)

		case "approle":
			roleID := strings.TrimSpace(c.GlobalString("role-id"))
			secretID := strings.TrimSpace(c.GlobalString("secret-id"))
			if roleID == "" {
				r, err := input("enter RoleID: ", false)
				if err != nil {
					return cli.NewExitError(fmt.Sprintf("error reading RoleID: %s", err), 1)
				}
				if r == "" {
					return cli.NewExitError("empty RoleID", 1)
				}
				roleID = r
			}
			if secretID == "" {
				s, err := input("enter SecretID: ", true)
				if err != nil {
					return cli.NewExitError(fmt.Sprintf("error reading SecretID: %s", err), 1)
				}
				if s == "" {
					return cli.NewExitError("empty SecretID", 1)
				}
				secretID = s
			}
			path = fmt.Sprintf("auth/%s/login", path)
			options := map[string]interface{}{
				"role_id":   roleID,
				"secret_id": secretID,
			}
			secret, err := client.Logical().Write(path, options)
			if err != nil {
				return cli.NewExitError(fmt.Sprintf("vault auth error: %s", err), 1)
			}
			client.SetToken(secret.Auth.ClientToken)

		default:
			return cli.NewExitError(fmt.Sprintf("unknown auth type: %s", authType), 1)
		}
		err = checkHealth(client)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("vault health check error: %s", err), 1)
		}

		_, err = client.Auth().Token().LookupSelf()
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("vault token lookup error: %s", err), 1)
		}

		//self.TokenIsRenewable()

		results := make(map[string]map[string]string)
		for _, sec := range secrets {
			res, err := client.Logical().Read(sec)
			if err != nil {
				return cli.NewExitError(fmt.Sprintf("error reading secret from vault: %s", err), 1)
			}
			results[sec] = make(map[string]string)
			for k, v := range res.Data {
				if s, ok := v.(string); ok {
					results[sec][k] = s
				} else {
					results[sec][k] = fmt.Sprintf("%s", v)
				}
			}
		}

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			for range sigChan {
				cancel()
			}
		}()

		env := make([]string, 0)
		forward := strings.TrimSpace(c.GlobalString("forward"))
		if forward == "*" {
			env = os.Environ()
		} else if forward != "" {
			m := make(map[string]bool)
			for _, k := range strings.FieldsFunc(forward, func(r rune) bool {
				return r == ',' || unicode.IsSpace(r)
			}) {
				m[k] = true
			}
			for _, v := range os.Environ() {
				v = strings.TrimLeft(v, "= ")
				if v != "" {
					spl := strings.SplitN(v, "=", 2)
					if m[spl[0]] {
						env = append(env, v)
					}
				}
			}
		}
		upcase := c.GlobalBool("upcase")
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		for _, sValues := range results {
			for k, v := range sValues {
				//fmt.Printf("%s => %s = %s\n", sKey, k, v)
				k = sanitize(k)
				if upcase {
					k = strings.ToUpper(k)
				}
				env = append(env, fmt.Sprintf("%s=%s", k, v))
			}
		}
		cmd.Env = env
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		err = cmd.Start()
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("failed to start command: %s", err), 1)
		}
		err = cmd.Wait()
		if err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				if e2, ok := e.Sys().(syscall.WaitStatus); ok {
					os.Exit(e2.ExitStatus())
				}
			}
			return cli.NewExitError(fmt.Sprintf("failed to execute command: %s", err), 1)
		}
		return nil
	}
	_ = app.Run(os.Args)
}

func sanitize(s string) string {
	// TODO
	return s
}

func checkHealth(client *api.Client) error {
	health, err := client.Sys().Health()
	if err != nil {
		return err
	}
	if !health.Initialized {
		return errors.New("vault is not initialized")
	}
	if health.Sealed {
		return errors.New("vault is sealed")
	}
	return nil
}

func input(text string, password bool) (string, error) {
	if password {
		fmt.Print(text)
		input, err := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(input)), nil
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(text)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}
