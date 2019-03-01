package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/go-homedir"
	"github.com/urfave/cli"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/sync/errgroup"
)

var Version string

func main() {
	app := cli.NewApp()
	app.Name = "vault-exec"
	app.Usage = "fetch secrets from vault and inject them as environment variables"
	app.UsageText = "vault-exec [options] cmd-to-execute"
	app.Version = Version
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
			Usage: "path of secret to be read from Vault (multiple times)",
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
			Name:   "prefix",
			Usage:  "prefix the environment variable keys with the name of secret",
			EnvVar: "PREFIX",
		},
		cli.StringFlag{
			Name:  "forward",
			Usage: "comma separated list of environment variable keys to forward from parent environment",
			Value: "*",
		},
		cli.StringFlag{
			Name:  "loglevel",
			Usage: "logging level",
			Value: "info",
		},
	}
	app.Action = func(c *cli.Context) error {
		zcfg := zap.NewProductionConfig()
		//zcfg := zap.NewDevelopmentConfig()
		loglevel := zapcore.DebugLevel
		_ = loglevel.Set(c.GlobalString("loglevel"))
		zcfg.Level.SetLevel(loglevel)
		zcfg.Sampling = nil
		l, err := zcfg.Build()
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("unable to initialize zap logger: %s", err), 1)
		}
		logger := l.Sugar()
		defer func() {
			logger.Sync()
		}()

		keys := c.GlobalStringSlice("secret")
		authType := strings.ToLower(c.GlobalString("method"))
		prefix := c.GlobalBool("prefix")
		path := strings.TrimSpace(c.GlobalString("path"))
		if path == "" {
			path = authType
		}
		args := c.Args()
		if len(args) == 0 {
			args = []string{"env"}
		}
		env := ForwardEnv(strings.TrimSpace(c.GlobalString("forward")))
		upcase := c.GlobalBool("upcase")
		config := api.DefaultConfig()
		config.Address = c.GlobalString("address")
		os.Unsetenv("VAULT_ADDR")
		client, err := api.NewClient(config)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("error creating vault client: %s", err), 1)
		}
		switch authType {
		case "token":
			logger.Info("token based authentication")
			tok := strings.TrimSpace(c.GlobalString("token"))
			if tok == "" {
				logger.Debug("token not found on command line or env")
				tokenPath, err := homedir.Expand("~/.vault-token")
				if err == nil {
					infos, err := os.Stat(tokenPath)
					if err == nil && infos.Mode().IsRegular() {
						content, err := ioutil.ReadFile(tokenPath)
						if err == nil {
							tok = string(content)
							logger.Infow("using token from file", "file", tokenPath)
						}
					} else {
						logger.Debug("unable to read file token")
					}
				} else {
					logger.Debugw("unable to expand ~/.vault-token", "error", err)
				}
				if tok == "" {
					t, err := input("enter token: ", true)
					if err != nil {
						return cli.NewExitError(fmt.Sprintf("error reading token: %s", err), 1)
					}
					tok = t
				}
				if tok == "" {
					return cli.NewExitError("empty token", 1)
				}
			}
			client.SetToken(tok)

		case "userpass", "ldap":
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

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			for range sigChan {
				cancel()
			}
		}()

		results := make(chan map[string]string)
		go func() {
			err := getSecrets(ctx, client, prefix, upcase, keys, logger, results)
			if e, ok := err.(TokenNotRenewedError); ok {
				logger.Errorw("can't renew token: giving up", "error", e.Err)
			} else if err != nil && err != context.Canceled {
				for _, line := range strings.Split(err.Error(), "\n") {
					line = strings.TrimSpace(line)
					if line != "" {
						logger.Errorw("vault error", "error", line)
					}
				}
			}
			cancel()
		}()
		var cmdCtx context.Context
		var cmdCancel context.CancelFunc
		var cmdGroup *errgroup.Group
		cmdSubCtx := context.Background()
		for {
			select {
			case <-ctx.Done():
				// global context is done, means that we received a signal to stop from user
				if cmdCancel != nil {
					// ask the command to stop
					cmdCancel()
					_ = cmdGroup.Wait()
				}
				return nil
			case <-cmdSubCtx.Done():
				cmdCancel()
				err := cmdGroup.Wait()
				if err == ErrCmdFinishedNoError {
					return nil
				}
				if err != ErrForceStop {
					return cli.NewExitError(err.Error(), 1)
				}

			case result, ok := <-results:
				if !ok {
					// ask the command to stop
					if cmdCancel != nil {
						cmdCancel()
						_ = cmdGroup.Wait()
					}
					return nil
				}
				if cmdCancel != nil {
					logger.Info("secrets updated from vault: restarting command")
					// ask the command to stop
					cmdCancel()
					err := cmdGroup.Wait()
					if err == ErrCmdFinishedNoError {
						return nil
					}
					if err != ErrForceStop {
						return cli.NewExitError(err.Error(), 1)
					}
				}
				cmdCtx, cmdCancel = context.WithCancel(ctx)
				cmdGroup, cmdSubCtx = errgroup.WithContext(cmdCtx)
				cmdGroup.Go(func() error {
					return execCmd(cmdCtx, args, result, env, logger)
				})
			}

		}
	}
	cli.OsExiter = func(code int) {
		os.Stdout.Sync()
		os.Stderr.Sync()
		time.Sleep(200 * time.Millisecond)
		os.Exit(code)
	}
	_ = app.Run(os.Args)
	os.Stdout.Sync()
	os.Stderr.Sync()
	time.Sleep(200 * time.Millisecond)
}

func sanitize(s string) string {
	return strings.Replace(s, "/", "_", -1)
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
