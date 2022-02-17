package secretstore

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	sdkhttpclient "github.com/grafana/grafana-plugin-sdk-go/backend/httpclient"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/components/simplejson"
	"github.com/grafana/grafana/pkg/infra/httpclient"
	"github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/services/accesscontrol"
	"github.com/grafana/grafana/pkg/services/secrets"
	"github.com/grafana/grafana/pkg/services/sqlstore"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/tsdb/azuremonitor/azcredentials"
)

type Service struct {
	Bus            bus.Bus
	SQLStore       *sqlstore.SQLStore
	SecretsService secrets.Service

	ptc               proxyTransportCache
	scDecryptionCache secureJSONDecryptionCache
}

type proxyTransportCache struct {
	cache map[int64]cachedRoundTripper
	sync.Mutex
}

type cachedRoundTripper struct {
	updated      time.Time
	roundTripper http.RoundTripper
}

type secureJSONDecryptionCache struct {
	cache map[int64]cachedDecryptedJSON
	sync.Mutex
}

type cachedDecryptedJSON struct {
	updated time.Time
	json    map[string]string
}

func ProvideService(bus bus.Bus, store *sqlstore.SQLStore, secretsService secrets.Service, ac accesscontrol.AccessControl) *Service {
	s := &Service{
		Bus:            bus,
		SQLStore:       store,
		SecretsService: secretsService,
		ptc: proxyTransportCache{
			cache: make(map[int64]cachedRoundTripper),
		},
		scDecryptionCache: secureJSONDecryptionCache{
			cache: make(map[int64]cachedDecryptedJSON),
		},
	}

	s.Bus.AddHandler(s.GetSecrets)
	s.Bus.AddHandler(s.GetSecretsByType)
	s.Bus.AddHandler(s.GetSecret)
	s.Bus.AddHandler(s.AddSecret)
	s.Bus.AddHandler(s.DeleteSecret)
	s.Bus.AddHandler(s.UpdateSecret)

	ac.RegisterAttributeScopeResolver(NewNameScopeResolver(store))

	return s
}

type SecretRetriever interface {
	GetSecret(ctx context.Context, query *models.GetSecretQuery) error
}

// NewNameScopeResolver provides an AttributeScopeResolver able to
// translate a scope prefixed with "secret:name:" into an id based scope.
func NewNameScopeResolver(db SecretRetriever) (string, accesscontrol.AttributeScopeResolveFunc) {
	scNameResolver := func(ctx context.Context, orgID int64, initialScope string) (string, error) {
		scNames := strings.Split(initialScope, ":")
		if scNames[0] != "secret" || len(scNames) != 3 {
			return "", accesscontrol.ErrInvalidScope
		}

		scName := scNames[2]
		// Special wildcard case
		if scName == "*" {
			return accesscontrol.Scope("secret", "id", "*"), nil
		}

		query := models.GetSecretQuery{Name: scName, OrgId: orgID}
		if err := db.GetSecret(ctx, &query); err != nil {
			return "", err
		}

		return accesscontrol.Scope("secret", "id", fmt.Sprintf("%v", query.Result.Id)), nil
	}

	return "secret:name:", scNameResolver
}

func (s *Service) GetSecret(ctx context.Context, query *models.GetSecretQuery) error {
	return s.SQLStore.GetSecret(ctx, query)
}

func (s *Service) GetSecrets(ctx context.Context, query *models.GetSecretsQuery) error {
	return s.SQLStore.GetSecrets(ctx, query)
}

func (s *Service) GetSecretsByType(ctx context.Context, query *models.GetSecretsByTypeQuery) error {
	return s.SQLStore.GetSecretsByType(ctx, query)
}

func (s *Service) AddSecret(ctx context.Context, cmd *models.AddSecretCommand) error {
	var err error
	cmd.EncryptedSecureJsonData, err = s.SecretsService.EncryptJsonData(ctx, cmd.SecureJsonData, secrets.WithoutScope())
	if err != nil {
		return err
	}

	return s.SQLStore.AddSecret(ctx, cmd)
}

func (s *Service) DeleteSecret(ctx context.Context, cmd *models.DeleteSecretCommand) error {
	return s.SQLStore.DeleteSecret(ctx, cmd)
}

func (s *Service) UpdateSecret(ctx context.Context, cmd *models.UpdateSecretCommand) error {
	var err error
	cmd.EncryptedSecureJsonData, err = s.SecretsService.EncryptJsonData(ctx, cmd.SecureJsonData, secrets.WithoutScope())
	if err != nil {
		return err
	}

	return s.SQLStore.UpdateSecret(ctx, cmd)
}

func (s *Service) GetHTTPClient(sc *models.Secret, provider httpclient.Provider) (*http.Client, error) {
	transport, err := s.GetHTTPTransport(sc, provider)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Timeout:   s.getTimeout(sc),
		Transport: transport,
	}, nil
}

func (s *Service) GetHTTPTransport(sc *models.Secret, provider httpclient.Provider,
	customMiddlewares ...sdkhttpclient.Middleware) (http.RoundTripper, error) {
	s.ptc.Lock()
	defer s.ptc.Unlock()

	if t, present := s.ptc.cache[sc.Id]; present && sc.Updated.Equal(t.updated) {
		return t.roundTripper, nil
	}

	opts, err := s.httpClientOptions(sc)
	if err != nil {
		return nil, err
	}

	opts.Middlewares = customMiddlewares

	rt, err := provider.GetTransport(*opts)
	if err != nil {
		return nil, err
	}

	s.ptc.cache[sc.Id] = cachedRoundTripper{
		roundTripper: rt,
		updated:      sc.Updated,
	}

	return rt, nil
}

func (s *Service) GetTLSConfig(sc *models.Secret, httpClientProvider httpclient.Provider) (*tls.Config, error) {
	opts, err := s.httpClientOptions(sc)
	if err != nil {
		return nil, err
	}
	return httpClientProvider.GetTLSConfig(*opts)
}

func (s *Service) DecryptedValues(sc *models.Secret) map[string]string {
	s.scDecryptionCache.Lock()
	defer s.scDecryptionCache.Unlock()

	if item, present := s.scDecryptionCache.cache[sc.Id]; present && sc.Updated.Equal(item.updated) {
		return item.json
	}

	json, err := s.SecretsService.DecryptJsonData(context.Background(), sc.SecureJsonData)
	if err != nil {
		return map[string]string{}
	}

	s.scDecryptionCache.cache[sc.Id] = cachedDecryptedJSON{
		updated: sc.Updated,
		json:    json,
	}

	return json
}

func (s *Service) DecryptedValue(sc *models.Secret, key string) (string, bool) {
	value, exists := s.DecryptedValues(sc)[key]
	return value, exists
}

func (s *Service) DecryptedBasicAuthPassword(sc *models.Secret) string {
	if value, ok := s.DecryptedValue(sc, "basicAuthPassword"); ok {
		return value
	}

	return sc.BasicAuthPassword
}

func (s *Service) DecryptedPassword(sc *models.Secret) string {
	if value, ok := s.DecryptedValue(sc, "password"); ok {
		return value
	}

	return sc.Password
}

func (s *Service) httpClientOptions(sc *models.Secret) (*sdkhttpclient.Options, error) {
	tlsOptions := s.scTLSOptions(sc)
	timeouts := &sdkhttpclient.TimeoutOptions{
		Timeout:               s.getTimeout(sc),
		DialTimeout:           sdkhttpclient.DefaultTimeoutOptions.DialTimeout,
		KeepAlive:             sdkhttpclient.DefaultTimeoutOptions.KeepAlive,
		TLSHandshakeTimeout:   sdkhttpclient.DefaultTimeoutOptions.TLSHandshakeTimeout,
		ExpectContinueTimeout: sdkhttpclient.DefaultTimeoutOptions.ExpectContinueTimeout,
		MaxConnsPerHost:       sdkhttpclient.DefaultTimeoutOptions.MaxConnsPerHost,
		MaxIdleConns:          sdkhttpclient.DefaultTimeoutOptions.MaxIdleConns,
		MaxIdleConnsPerHost:   sdkhttpclient.DefaultTimeoutOptions.MaxIdleConnsPerHost,
		IdleConnTimeout:       sdkhttpclient.DefaultTimeoutOptions.IdleConnTimeout,
	}
	opts := &sdkhttpclient.Options{
		Timeouts: timeouts,
		Headers:  s.getCustomHeaders(sc.JsonData, s.DecryptedValues(sc)),
		Labels: map[string]string{
			"datasource_name": sc.Name,
			"datasource_uid":  sc.Uid,
		},
		TLS: &tlsOptions,
	}

	if sc.JsonData != nil {
		opts.CustomOptions = sc.JsonData.MustMap()
	}

	if sc.BasicAuth {
		opts.BasicAuth = &sdkhttpclient.BasicAuthOptions{
			User:     sc.BasicAuthUser,
			Password: s.DecryptedBasicAuthPassword(sc),
		}
	} else if sc.User != "" {
		opts.BasicAuth = &sdkhttpclient.BasicAuthOptions{
			User:     sc.User,
			Password: s.DecryptedPassword(sc),
		}
	}

	if sc.JsonData != nil {
		credentials, err := azcredentials.FromDatasourceData(sc.JsonData.MustMap(), s.DecryptedValues(sc))
		if err != nil {
			err = fmt.Errorf("invalid Azure credentials: %s", err)
			return nil, err
		}

		if credentials != nil {
			opts.CustomOptions["_azureCredentials"] = credentials
		}
	}

	if sc.JsonData != nil && sc.JsonData.Get("sigV4Auth").MustBool(false) && setting.SigV4AuthEnabled {
		opts.SigV4 = &sdkhttpclient.SigV4Config{
			Service:       awsServiceNamespace(sc.Type),
			Region:        sc.JsonData.Get("sigV4Region").MustString(),
			AssumeRoleARN: sc.JsonData.Get("sigV4AssumeRoleArn").MustString(),
			AuthType:      sc.JsonData.Get("sigV4AuthType").MustString(),
			ExternalID:    sc.JsonData.Get("sigV4ExternalId").MustString(),
			Profile:       sc.JsonData.Get("sigV4Profile").MustString(),
		}

		if val, exists := s.DecryptedValue(sc, "sigV4AccessKey"); exists {
			opts.SigV4.AccessKey = val
		}

		if val, exists := s.DecryptedValue(sc, "sigV4SecretKey"); exists {
			opts.SigV4.SecretKey = val
		}
	}

	return opts, nil
}

func (s *Service) scTLSOptions(sc *models.Secret) sdkhttpclient.TLSOptions {
	var tlsSkipVerify, tlsClientAuth, tlsAuthWithCACert bool
	var serverName string

	if sc.JsonData != nil {
		tlsClientAuth = sc.JsonData.Get("tlsAuth").MustBool(false)
		tlsAuthWithCACert = sc.JsonData.Get("tlsAuthWithCACert").MustBool(false)
		tlsSkipVerify = sc.JsonData.Get("tlsSkipVerify").MustBool(false)
		serverName = sc.JsonData.Get("serverName").MustString()
	}

	opts := sdkhttpclient.TLSOptions{
		InsecureSkipVerify: tlsSkipVerify,
		ServerName:         serverName,
	}

	if tlsClientAuth || tlsAuthWithCACert {
		if tlsAuthWithCACert {
			if val, exists := s.DecryptedValue(sc, "tlsCACert"); exists && len(val) > 0 {
				opts.CACertificate = val
			}
		}

		if tlsClientAuth {
			if val, exists := s.DecryptedValue(sc, "tlsClientCert"); exists && len(val) > 0 {
				opts.ClientCertificate = val
			}
			if val, exists := s.DecryptedValue(sc, "tlsClientKey"); exists && len(val) > 0 {
				opts.ClientKey = val
			}
		}
	}

	return opts
}

func (s *Service) getTimeout(sc *models.Secret) time.Duration {
	timeout := 0
	if sc.JsonData != nil {
		timeout = sc.JsonData.Get("timeout").MustInt()
		if timeout <= 0 {
			if timeoutStr := sc.JsonData.Get("timeout").MustString(); timeoutStr != "" {
				if t, err := strconv.Atoi(timeoutStr); err == nil {
					timeout = t
				}
			}
		}
	}
	if timeout <= 0 {
		return sdkhttpclient.DefaultTimeoutOptions.Timeout
	}

	return time.Duration(timeout) * time.Second
}

// getCustomHeaders returns a map with all the to be set headers
// The map key represents the HeaderName and the value represents this header's value
func (s *Service) getCustomHeaders(jsonData *simplejson.Json, decryptedValues map[string]string) map[string]string {
	headers := make(map[string]string)
	if jsonData == nil {
		return headers
	}

	index := 1
	for {
		headerNameSuffix := fmt.Sprintf("httpHeaderName%d", index)
		headerValueSuffix := fmt.Sprintf("httpHeaderValue%d", index)

		key := jsonData.Get(headerNameSuffix).MustString()
		if key == "" {
			// No (more) header values are available
			break
		}

		if val, ok := decryptedValues[headerValueSuffix]; ok {
			headers[key] = val
		}
		index++
	}

	return headers
}

func awsServiceNamespace(scType string) string {
	switch scType {
	case models.DS_ES, models.DS_ES_OPEN_DISTRO, models.DS_ES_OPENSEARCH:
		return "es"
	case models.DS_PROMETHEUS:
		return "aps"
	default:
		panic(fmt.Sprintf("Unsupported datasource %q", scType))
	}
}
