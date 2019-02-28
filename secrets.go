package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

func getSecrets(ctx context.Context, client *api.Client, prefix bool, upcase bool, keys []string, logger *zap.SugaredLogger, results chan map[string]string) (rerr error) {
	g, lctx := errgroup.WithContext(ctx)
	defer func() {
		err := g.Wait()
		close(results)
		if err != nil {
			rerr = err
		}
	}()

	self, err := client.Auth().Token().RenewSelf(0)
	if err != nil {
		return fmt.Errorf("vault token lookup error: %s", err)
	}
	renewable, _ := self.TokenIsRenewable()
	if renewable {
		logger.Debugw("token is renewable")
		renewer, _ := client.NewRenewer(&api.RenewerInput{
			Secret: self,
		})
		g.Go(func() error {
			renewer.Renew()
			return nil
		})
		g.Go(func() error {
			<-lctx.Done()
			renewer.Stop()
			return nil
		})
		g.Go(func() error {
			for {
				select {
				case err := <-renewer.DoneCh():
					if err != nil {
						return fmt.Errorf("can't renew token: %s", err)
					}
					return errors.New("can't renew token anymore")
				case renewal := <-renewer.RenewCh():
					logger.Debugw("token renewed", "at", renewal.RenewedAt.Format(time.RFC3339))
				}
			}
		})
	} else {
		logger.Debugw("token is not renewable")
	}
	previousResult := make(map[string]string)
	for {
		subg, llctx := errgroup.WithContext(lctx)
		result, err := getSecretsHelper(llctx, subg, client, prefix, upcase, keys, logger)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(result, previousResult) {
			previousResult = result
			select {
			case results <- result:
			case <-lctx.Done():
				return lctx.Err()
			}
		}
		subg.Wait()
		select {
		case <-lctx.Done():
			return lctx.Err()
		default:
		}
	}
}

func getSecretsHelper(ctx context.Context, g *errgroup.Group, client *api.Client, prefix bool, upcase bool, keys []string, logger *zap.SugaredLogger) (map[string]string, error) {
	fullResults := make(map[string]map[string]string)
	for _, s := range keys {
		sec := s
		res, err := client.Logical().Read(sec)
		if err != nil {
			return nil, fmt.Errorf("error reading secret from vault: %s", err)
		}
		fullResults[sec] = make(map[string]string)
		for k, v := range res.Data {
			if s, ok := v.(string); ok {
				fullResults[sec][k] = s
			} else {
				fullResults[sec][k] = fmt.Sprintf("%s", v)
			}
		}
		renewable, _ := res.TokenIsRenewable()
		if renewable {
			logger.Debugw("secret is renewable", "secret", sec)
			renewer, _ := client.NewRenewer(&api.RenewerInput{
				Secret: res,
			})
			g.Go(func() error {
				renewer.Renew()
				return nil
			})
			g.Go(func() error {
				<-ctx.Done()
				renewer.Stop()
				return nil
			})
			g.Go(func() error {
				for {
					select {
					case err := <-renewer.DoneCh():
						if err != nil {
							logger.Debugw("can't renew secret", "secret", sec, "error", err)
						}
						return err
					case renewal := <-renewer.RenewCh():
						logger.Debugw("secret renewed", "secret", sec, "at", renewal.RenewedAt.Format(time.RFC3339))
					}
				}
			})
		} else {
			logger.Debugw("secret is not renewable", "secret", sec)
			g.Go(func() error {
				<-ctx.Done()
				return nil
			})
		}
	}

	result := make(map[string]string)

	for secretKey, sValues := range fullResults {
		for k, v := range sValues {
			if prefix {
				k = secretKey + "_" + k
			}
			//fmt.Printf("%s => %s = %s\n", sKey, k, v)
			k = sanitize(k)
			if upcase {
				k = strings.ToUpper(k)
			}
			result[k] = v
		}
	}
	return result, nil
}
