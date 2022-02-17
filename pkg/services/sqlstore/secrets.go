package sqlstore

import (
	"context"
	"fmt"
	"time"

	"github.com/grafana/grafana/pkg/events"
	"github.com/grafana/grafana/pkg/infra/metrics"
	"github.com/grafana/grafana/pkg/models"
	"xorm.io/xorm"
)

// GetSecret adds a secret to the query model by querying by org_id as well as
// either uid (preferred), id, or name and is added to the bus.
func (ss *SQLStore) GetSecret(ctx context.Context, query *models.GetSecretQuery) error {
	metrics.MDBSecretQueryByID.Inc()

	return ss.WithDbSession(ctx, func(sess *DBSession) error {
		if query.OrgId == 0 || (query.Id == 0 && len(query.Name) == 0 && len(query.Uid) == 0) {
			return models.ErrSecretIdentifierNotSet
		}

		secret := &models.Secret{Name: query.Name, OrgId: query.OrgId, Id: query.Id}
		has, err := sess.Get(secret)

		if err != nil {
			sqlog.Error("Failed getting data source", "err", err, "uid", query.Uid, "id", query.Id, "name", query.Name, "orgId", query.OrgId)
			return err
		} else if !has {
			return models.ErrSecretNotFound
		}

		query.Result = secret

		return nil
	})
}

func (ss *SQLStore) GetSecrets(ctx context.Context, query *models.GetSecretsQuery) error {
	var sess *xorm.Session
	return ss.WithDbSession(ctx, func(dbSess *DBSession) error {
		if query.SecretLimit <= 0 {
			sess = dbSess.Where("org_id=?", query.OrgId).Asc("name")
		} else {
			sess = dbSess.Limit(query.SecretLimit, 0).Where("org_id=?", query.OrgId).Asc("name")
		}

		query.Result = make([]*models.Secret, 0)
		return sess.Find(&query.Result)
	})
}

// GetSecretsByType returns all datasources for a given type or an error if the specified type is an empty string
func (ss *SQLStore) GetSecretsByType(ctx context.Context, query *models.GetSecretsByTypeQuery) error {
	if query.Type == "" {
		return fmt.Errorf("datasource type cannot be empty")
	}

	query.Result = make([]*models.Secret, 0)
	return ss.WithDbSession(ctx, func(sess *DBSession) error {
		return sess.Where("type=?", query.Type).Asc("id").Find(&query.Result)
	})
}

// DeleteSecret removes a secret by org_id as well as either uid (preferred), id, or name
// and is added to the bus.
func (ss *SQLStore) DeleteSecret(ctx context.Context, cmd *models.DeleteSecretCommand) error {
	params := make([]interface{}, 0)

	makeQuery := func(sql string, p ...interface{}) {
		params = append(params, sql)
		params = append(params, p...)
	}

	switch {
	case cmd.OrgID == 0:
		return models.ErrSecretIdentifierNotSet
	case cmd.ID != 0:
		makeQuery("DELETE FROM data_source WHERE id=? and org_id=?", cmd.ID, cmd.OrgID)
	case cmd.Name != "":
		makeQuery("DELETE FROM data_source WHERE name=? and org_id=?", cmd.Name, cmd.OrgID)
	default:
		return models.ErrSecretIdentifierNotSet
	}

	return ss.WithTransactionalDbSession(ctx, func(sess *DBSession) error {
		result, err := sess.Exec(params...)
		cmd.DeletedSecretsCount, _ = result.RowsAffected()

		sess.publishAfterCommit(&events.SecretDeleted{
			Timestamp: time.Now(),
			Name:      cmd.Name,
			ID:        cmd.ID,
			OrgID:     cmd.OrgID,
		})

		return err
	})
}

func (ss *SQLStore) AddSecret(ctx context.Context, cmd *models.AddSecretCommand) error {
	return ss.WithTransactionalDbSession(ctx, func(sess *DBSession) error {
		existing := models.Secret{OrgId: cmd.OrgId, Name: cmd.Name}
		has, _ := sess.Get(&existing)

		if has {
			return models.ErrSecretNameExists
		}

		s := &models.Secret{
			OrgId:          cmd.OrgId,
			Name:           cmd.Name,
			SecureJsonData: cmd.EncryptedSecureJsonData,
			Created:        time.Now(),
			Updated:        time.Now(),
			Version:        1,
			ReadOnly:       cmd.ReadOnly,
		}

		cmd.Result = s

		sess.publishAfterCommit(&events.SecretCreated{
			Timestamp: time.Now(),
			Name:      cmd.Name,
			ID:        s.Id,
			OrgID:     cmd.OrgId,
		})
		return nil
	})
}

func (ss *SQLStore) UpdateSecret(ctx context.Context, cmd *models.UpdateSecretCommand) error {
	return ss.WithTransactionalDbSession(ctx, func(sess *DBSession) error {
		s := &models.Secret{
			Id:             cmd.Id,
			OrgId:          cmd.OrgId,
			Name:           cmd.Name,
			SecureJsonData: cmd.EncryptedSecureJsonData,
			Updated:        time.Now(),
			ReadOnly:       cmd.ReadOnly,
			Version:        cmd.Version + 1,
		}

		sess.UseBool("is_default")
		sess.UseBool("basic_auth")
		sess.UseBool("with_credentials")
		sess.UseBool("read_only")
		// Make sure password are zeroed out if empty. We do this as we want to migrate passwords from
		// plain text fields to SecureJsonData.
		sess.MustCols("password")
		sess.MustCols("basic_auth_password")
		sess.MustCols("user")

		var updateSession *xorm.Session
		if cmd.Version != 0 {
			// the reason we allow cmd.version > db.version is make it possible for people to force
			// updates to secrets using the secret.yaml file without knowing exactly what version
			// a secret have in the db.
			updateSession = sess.Where("id=? and org_id=? and version < ?", s.Id, s.OrgId, s.Version)
		} else {
			updateSession = sess.Where("id=? and org_id=?", s.Id, s.OrgId)
		}

		affected, err := updateSession.Update(s)
		if err != nil {
			return err
		}

		if affected == 0 {
			return models.ErrSecretUpdatingOldVersion
		}

		cmd.Result = s
		return err
	})
}
