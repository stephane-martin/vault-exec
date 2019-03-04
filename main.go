package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/stephane-martin/vault-exec/lib"
	"github.com/urfave/cli"
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
			Usage:  "type of authentication",
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
			Usage:  "Vault username or RoleID",
			Value:  "",
			EnvVar: "VAULT_USERNAME",
		},
		cli.StringFlag{
			Name:   "password",
			Usage:  "Vault password or SecretID",
			Value:  "",
			EnvVar: "VAULT_PASSWORD",
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
		logger, err := lib.Logger(c.GlobalString("loglevel"))
		if err != nil {
			return cli.NewExitError(err.Error(), 1)
		}
		defer logger.Sync()

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
		env := lib.ForwardEnv(strings.TrimSpace(c.GlobalString("forward")))
		upcase := c.GlobalBool("upcase")
		os.Unsetenv("VAULT_ADDR")

		client, err := lib.Auth(authType, c.GlobalString("address"), path, c.GlobalString("token"), c.GlobalString("username"), c.GlobalString("password"), logger)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("auth failed: %s", err), 1)
		}

		err = lib.CheckHealth(client)
		if err != nil {
			return cli.NewExitError(fmt.Sprintf("vault health check error: %s", err), 1)
		}
		ctx, cancel := lib.GlobalContext()
		results := make(chan map[string]string)
		go func() {
			err := lib.GetSecrets(ctx, client, prefix, upcase, keys, logger, results)
			if e, ok := err.(lib.TokenNotRenewedError); ok {
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
				if err == lib.ErrCmdFinishedNoError {
					return nil
				}
				if err != lib.ErrForceStop {
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
					if err == lib.ErrCmdFinishedNoError {
						return nil
					}
					if err != lib.ErrForceStop {
						return cli.NewExitError(err.Error(), 1)
					}
				}
				cmdCtx, cmdCancel = context.WithCancel(ctx)
				cmdGroup, cmdSubCtx = errgroup.WithContext(cmdCtx)
				cmdGroup.Go(func() error {
					return lib.ExecCmd(cmdCtx, args, result, env, logger)
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
