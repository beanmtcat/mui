package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"mui/internal/shared"
)

// AppliedDeployment returns what the server's last successful apply put in
// place. known is false for a server that has not completed one since this was
// first recorded.
func (s *Store) AppliedDeployment(serverID string) (nodes map[string]shared.NodeDeployment, known bool, err error) {
	var raw string
	err = s.DB.QueryRow(`SELECT data FROM mui_server_applied WHERE server_id=$1`, serverID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	nodes = map[string]shared.NodeDeployment{}
	return nodes, true, json.Unmarshal([]byte(raw), &nodes)
}

func (s *Store) SetAppliedDeployment(serverID string, nodes map[string]shared.NodeDeployment) error {
	if nodes == nil {
		nodes = map[string]shared.NodeDeployment{}
	}
	_, err := s.DB.Exec(`INSERT INTO mui_server_applied(server_id,data) VALUES($1,$2) ON CONFLICT(server_id) DO UPDATE SET data=excluded.data`, serverID, Marshal(nodes))
	return err
}

func (s *Store) Servers() ([]shared.Server, error) {
	list, err := queryJSON[shared.Server](s.DB, `SELECT data FROM mui_servers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	totals, err := s.totals(`SELECT server_id,rx,tx FROM mui_server_totals`)
	if err != nil {
		return nil, err
	}
	for i := range list {
		list[i].NetworkRx, list[i].NetworkTx = totals[list[i].ID][0], totals[list[i].ID][1]
	}
	return list, nil
}

func (s *Store) Server(id string) (shared.Server, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT data FROM mui_servers WHERE id=$1`, id).Scan(&raw)
	var v shared.Server
	if err == nil {
		err = json.Unmarshal([]byte(raw), &v)
	}
	return v, err
}

func (s *Store) PutServer(v shared.Server) error {
	_, err := s.DB.Exec(`UPDATE mui_servers SET data=$1,revision=$2 WHERE id=$3`, Marshal(v), v.Revision, v.ID)
	return err
}

// A previously copied installer must not keep its old core selection after
// the server's role changes. Save the new role and revoke that one-time guide
// in the same statement.
func (s *Store) PutServerAndInvalidateEnrollment(v shared.Server) error {
	_, err := s.DB.Exec(`UPDATE mui_servers SET data=$1,revision=$2,enroll_hash='',enroll_expires=0 WHERE id=$3`, Marshal(v), v.Revision, v.ID)
	return err
}

func (s *Store) Nodes(serverID string) ([]shared.Node, error) {
	if serverID == "" {
		return queryJSON[shared.Node](s.DB, `SELECT data FROM mui_nodes ORDER BY id`)
	}
	return queryJSON[shared.Node](s.DB, `SELECT data FROM mui_nodes WHERE server_id=$1 ORDER BY id`, serverID)
}

func (s *Store) NodeTemplates() ([]shared.NodeTemplate, error) {
	return queryJSON[shared.NodeTemplate](s.DB, `SELECT data FROM mui_node_templates ORDER BY id`)
}

func (s *Store) NodeTemplate(id string) (shared.NodeTemplate, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT data FROM mui_node_templates WHERE id=$1`, id).Scan(&raw)
	var v shared.NodeTemplate
	if err == nil {
		err = json.Unmarshal([]byte(raw), &v)
	}
	return v, err
}

func (s *Store) NodeTemplateSecret(id string) (string, error) {
	var secret string
	if err := s.DB.QueryRow(`SELECT secret FROM mui_node_templates WHERE id=$1`, id).Scan(&secret); err != nil {
		return "", err
	}
	if secret == "" {
		return "", nil
	}
	return s.Decrypt(secret)
}

func (s *Store) NodeTemplateShadowTLSSecret(id string) (string, error) {
	return s.optionalSecret(`SELECT shadow_tls_secret FROM mui_node_templates WHERE id=$1`, id)
}

func (s *Store) optionalSecret(query, id string) (string, error) {
	var raw string
	if err := s.DB.QueryRow(query, id).Scan(&raw); err != nil {
		return "", err
	}
	if raw == "" {
		return "", nil
	}
	return s.Decrypt(raw)
}

func (s *Store) PutNodeTemplate(v shared.NodeTemplate, password, shadowTLSPassword string) error {
	secret := ""
	shadowSecret := ""
	var err error
	if password != "" {
		secret, err = s.Encrypt(password)
		if err != nil {
			return err
		}
	}
	if shadowTLSPassword != "" {
		shadowSecret, err = s.Encrypt(shadowTLSPassword)
		if err != nil {
			return err
		}
	}
	_, err = s.DB.Exec(`INSERT INTO mui_node_templates(id,data,secret,shadow_tls_secret) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET data=excluded.data,secret=excluded.secret,shadow_tls_secret=excluded.shadow_tls_secret`, v.ID, Marshal(v), secret, shadowSecret)
	return err
}

func (s *Store) DeleteNodeTemplate(id string) error {
	_, err := s.DB.Exec(`DELETE FROM mui_node_templates WHERE id=$1`, id)
	return err
}

func (s *Store) Node(id string) (shared.Node, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT data FROM mui_nodes WHERE id=$1`, id).Scan(&raw)
	var v shared.Node
	if err == nil {
		err = json.Unmarshal([]byte(raw), &v)
	}
	return v, err
}

func (s *Store) NodeSecret(id string) (string, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT secret FROM mui_nodes WHERE id=$1`, id).Scan(&raw)
	if err != nil {
		return "", err
	}
	return s.Decrypt(raw)
}

func (s *Store) NodeShadowTLSSecret(id string) (string, error) {
	return s.optionalSecret(`SELECT shadow_tls_secret FROM mui_nodes WHERE id=$1`, id)
}

// SubscriptionUser deterministically derives a separate login for each
// subscription/node pair. The server secret already protects node secrets, so
// no extra plaintext credential table is needed.
func (s *Store) SubscriptionUser(n shared.Node, subscriptionID string) shared.NodeUser {
	derive := func(purpose string) []byte {
		mac := hmac.New(sha256.New, s.key)
		_, _ = mac.Write([]byte("mui-user-v1\x00" + purpose + "\x00" + n.ID + "\x00" + subscriptionID))
		return mac.Sum(nil)
	}
	key := derive("login")
	if n.Protocol == "ss" && n.Method == "2022-blake3-aes-128-gcm" {
		key = key[:16]
	}
	password := base64.RawURLEncoding.EncodeToString(key)
	if n.Protocol == "ss" {
		password = base64.StdEncoding.EncodeToString(key)
	}
	return shared.NodeUser{
		SubscriptionID:    subscriptionID,
		Name:              "mui-" + n.ID + "-" + subscriptionID,
		Password:          password,
		ShadowTLSPassword: base64.RawURLEncoding.EncodeToString(derive("shadowtls")),
	}
}

func (s *Store) PutNode(v shared.Node, password string) error {
	secret, err := s.Encrypt(password)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(`INSERT INTO mui_nodes(id,server_id,data,secret) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET server_id=excluded.server_id,data=excluded.data,secret=excluded.secret`, v.ID, v.ServerID, Marshal(v), secret)
	return err
}

func (s *Store) PutNodeWithShadowTLS(v shared.Node, password, shadowTLSPassword string) error {
	secret, err := s.Encrypt(password)
	if err != nil {
		return err
	}
	shadowSecret := ""
	if shadowTLSPassword != "" {
		shadowSecret, err = s.Encrypt(shadowTLSPassword)
		if err != nil {
			return err
		}
	}
	_, err = s.DB.Exec(`INSERT INTO mui_nodes(id,server_id,data,secret,shadow_tls_secret) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET server_id=excluded.server_id,data=excluded.data,secret=excluded.secret,shadow_tls_secret=excluded.shadow_tls_secret`, v.ID, v.ServerID, Marshal(v), secret, shadowSecret)
	return err
}

func (s *Store) Certificates() ([]shared.Certificate, error) {
	return queryJSON[shared.Certificate](s.DB, `SELECT data FROM mui_certificates ORDER BY id`)
}

func (s *Store) Certificate(id string) (shared.Certificate, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT data FROM mui_certificates WHERE id=$1`, id).Scan(&raw)
	var v shared.Certificate
	if err == nil {
		err = json.Unmarshal([]byte(raw), &v)
	}
	return v, err
}

func (s *Store) CertificateKey(id string) (string, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT secret FROM mui_certificates WHERE id=$1`, id).Scan(&raw)
	if err != nil {
		return "", err
	}
	return s.Decrypt(raw)
}

func (s *Store) PutCertificate(v shared.Certificate) error {
	secret, err := s.Encrypt(v.Key)
	if err != nil {
		return err
	}
	v.Key = ""
	_, err = s.DB.Exec(`INSERT INTO mui_certificates(id,data,secret) VALUES($1,$2,$3)`, v.ID, Marshal(v), secret)
	return err
}

// UpdateCertificate stores the certificate and any node status changes in one
// transaction. Node secrets stay in their existing encrypted columns.
func (s *Store) UpdateCertificate(v shared.Certificate, pendingNodes []shared.Node) error {
	secret, err := s.Encrypt(v.Key)
	if err != nil {
		return err
	}
	v.Key = ""
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE mui_certificates SET data=$1,secret=$2 WHERE id=$3`, Marshal(v), secret, v.ID)
	if err != nil {
		return err
	}
	if rows, err := result.RowsAffected(); err != nil {
		return err
	} else if rows == 0 {
		return sql.ErrNoRows
	}
	for _, n := range pendingNodes {
		if _, err := tx.Exec(`UPDATE mui_nodes SET data=$1 WHERE id=$2`, Marshal(n), n.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Rules(serverID string) ([]shared.FirewallRule, error) {
	if serverID == "" {
		return queryJSON[shared.FirewallRule](s.DB, `SELECT data FROM mui_firewall_rules ORDER BY id`)
	}
	return queryJSON[shared.FirewallRule](s.DB, `SELECT data FROM mui_firewall_rules WHERE server_id=$1 ORDER BY id`, serverID)
}

func (s *Store) Forwards(serverID string) ([]shared.ForwardRule, error) {
	var list []shared.ForwardRule
	var err error
	if serverID == "" {
		list, err = queryJSON[shared.ForwardRule](s.DB, `SELECT data FROM mui_forwards ORDER BY id`)
	} else {
		list, err = queryJSON[shared.ForwardRule](s.DB, `SELECT data FROM mui_forwards WHERE server_id=$1 ORDER BY id`, serverID)
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.Query(`SELECT forward_id,uplink,downlink FROM mui_forward_totals`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	totals := map[string][2]int64{}
	for rows.Next() {
		var id string
		var up, down int64
		if err := rows.Scan(&id, &up, &down); err != nil {
			return nil, err
		}
		totals[id] = [2]int64{up, down}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range list {
		list[i].Uplink, list[i].Downlink = totals[list[i].ID][0], totals[list[i].ID][1]
	}
	return list, nil
}

func (s *Store) Forward(id string) (shared.ForwardRule, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT data FROM mui_forwards WHERE id=$1`, id).Scan(&raw)
	var v shared.ForwardRule
	if err == nil {
		err = json.Unmarshal([]byte(raw), &v)
	}
	return v, err
}

func (s *Store) PutForward(v shared.ForwardRule) error {
	v.Uplink, v.Downlink = 0, 0
	_, err := s.DB.Exec(`INSERT INTO mui_forwards(id,server_id,data) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET server_id=excluded.server_id,data=excluded.data`, v.ID, v.ServerID, Marshal(v))
	return err
}

// ownedIDs resolves, in one query, which of ids belong to serverID in table.
// Table and column names are fixed literals from the callers, never input.
func ownedIDs(ctx context.Context, tx *sql.Tx, table, serverID string, ids []string) (map[string]bool, error) {
	seen := map[string]bool{}
	unique := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != "" && !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}
	out := map[string]bool{}
	if len(unique) == 0 {
		return out, nil
	}
	args := make([]any, 0, len(unique)+1)
	args = append(args, serverID)
	placeholders := make([]string, 0, len(unique))
	for i, id := range unique {
		args = append(args, id)
		placeholders = append(placeholders, "$"+strconv.Itoa(i+2))
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM `+table+` WHERE server_id=$1 AND id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

func (s *Store) Subscriptions() ([]shared.Subscription, error) {
	return queryJSON[shared.Subscription](s.DB, `SELECT data FROM mui_subscriptions ORDER BY id`)
}

func (s *Store) SubscriptionByToken(token string) (shared.Subscription, error) {
	var raw string
	err := s.DB.QueryRow(`SELECT data FROM mui_subscriptions WHERE token_hash=$1`, Hash(token)).Scan(&raw)
	var v shared.Subscription
	if err == nil {
		err = json.Unmarshal([]byte(raw), &v)
	}
	return v, err
}
