package db

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"math"
	"os"
	"tariff-module-backend/internal/model"
)

var DB *pgxpool.Pool

// Вернуть при подключении БД

func Connect() {
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	dbname := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", user, password, host, port, dbname)

	var err error
	DB, err = pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("Не удалось подключиться к БД: %v", err)
	}

	fmt.Println("Подключение к PostgreSQL успешно!")
}

// Тарифы

// GetAllTariffs - возвращает список всех тарифов из базы данных
func GetAllTariffs() ([]model.Tariff, error) {
	query := `
	   SELECT id, name, fixed_fee, percent_fee, min_fee, max_fee
	   FROM tariffs
	   ORDER BY id
	`

	rows, err := DB.Query(context.Background(), query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tariffs []model.Tariff

	for rows.Next() {
		var t model.Tariff
		if err := rows.Scan(&t.ID, &t.Name, &t.FixedFee, &t.PercentFee, &t.MinFee, &t.MaxFee); err != nil {
			return nil, err
		}
		tariffs = append(tariffs, t)
	}

	return tariffs, nil
}

// GetTariffByClientID получает тариф по clientId
func GetTariffByClientID(clientID string) (model.Tariff, error) {
	query := `
        SELECT t.id, t.name, t.fixed_fee, t.percent_fee, t.min_fee, t.max_fee
        FROM clients c
        JOIN tariffs t ON c.tariff_id = t.id
        WHERE c.client_id = $1
    `
	var tariff model.Tariff
	row := DB.QueryRow(context.Background(), query, clientID)
	err := row.Scan(&tariff.ID, &tariff.Name, &tariff.FixedFee, &tariff.PercentFee, &tariff.MinFee, &tariff.MaxFee)
	if err != nil {
		return model.Tariff{}, fmt.Errorf("ошибка при получении тарифа: %w", err)
	}

	return tariff, nil
}

// GetTariffByID - получение конкретного тарифа
func GetTariffByID(id int) (model.Tariff, error) {
	row := DB.QueryRow(context.Background(), `
		SELECT id, name, fixed_fee, percent_fee, min_fee, max_fee, calc_mode
		FROM tariffs
		WHERE id = $1
	`, id)

	var tariff model.Tariff
	err := row.Scan(
		&tariff.ID,
		&tariff.Name,
		&tariff.FixedFee,
		&tariff.PercentFee,
		&tariff.MinFee,
		&tariff.MaxFee,
		&tariff.CalcMode,
	)
	return tariff, err
}

// CreateTariff - добавление тарифа в БД
func CreateTariff(tariff model.Tariff) error {
	_, err := DB.Exec(context.Background(), `
		INSERT INTO tariffs (name, fixed_fee, percent_fee, min_fee, max_fee, calc_mode)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, tariff.Name, tariff.FixedFee, tariff.PercentFee, tariff.MinFee, tariff.MaxFee, tariff.CalcMode)

	return err
}

// UpdateTariff - изменение конкретного тарифа
func UpdateTariff(id int, t model.Tariff) error {
	_, err := DB.Exec(context.Background(), `
		UPDATE tariffs
		SET name = $1,
		    fixed_fee = $2,
		    percent_fee = $3,
		    min_fee = $4,
		    max_fee = $5,
		    calc_mode = $6
		WHERE id = $7
	`,
		t.Name,
		t.FixedFee,
		t.PercentFee,
		t.MinFee,
		t.MaxFee,
		t.CalcMode,
		id,
	)
	return err
}

// DeleteTariff - удаление конкретного тарифа
func DeleteTariff(id int) error {
	_, err := DB.Exec(context.Background(), `
		DELETE FROM tariffs WHERE id = $1
	`, id)
	return err
}

// Пороговые правила

// GetAllThresholdRules - получение правил для порогов всех тарифов
func GetAllThresholdRules() ([]model.ThresholdRule, error) {
	rows, err := DB.Query(context.Background(), `
		SELECT id, tariff_id, from_count, to_count, percent_fee, fixed_fee, min_fee, max_fee,
		       calc_mode, mcc, client_type, account_type, op_type
		FROM threshold_rules
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []model.ThresholdRule
	for rows.Next() {
		var r model.ThresholdRule
		err := rows.Scan(
			&r.ID,
			&r.TariffID,
			&r.FromCount,
			&r.ToCount,
			&r.PercentFee,
			&r.FixedFee,
			&r.MinFee,
			&r.MaxFee,
			&r.CalcMode,
			&r.MCC,
			&r.ClientType,
			&r.AccountType,
			&r.OpType,
		)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// GetThresholdRulesByTariffID - получение правил для порогов конкретного тарифа
func GetThresholdRulesByTariffID(tariffID int) ([]model.ThresholdRule, error) {
	rows, err := DB.Query(context.Background(), `
		SELECT id, tariff_id, from_count, to_count, percent_fee, fixed_fee, min_fee, max_fee,
		       calc_mode, mcc, client_type, account_type, op_type
		FROM threshold_rules
		WHERE tariff_id = $1
	`, tariffID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []model.ThresholdRule
	for rows.Next() {
		var r model.ThresholdRule
		err := rows.Scan(
			&r.ID,
			&r.TariffID,
			&r.FromCount,
			&r.ToCount,
			&r.PercentFee,
			&r.FixedFee,
			&r.MinFee,
			&r.MaxFee,
			&r.CalcMode,
			&r.MCC,
			&r.ClientType,
			&r.AccountType,
			&r.OpType,
		)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// CreateThresholdRule - добавление нового правила для порога
func CreateThresholdRule(rule model.ThresholdRule) error {
	_, err := DB.Exec(context.Background(), `
		INSERT INTO threshold_rules 
		(tariff_id, from_count, to_count, percent_fee, fixed_fee, min_fee, max_fee, calc_mode, mcc, client_type, account_type, op_type)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`,
		rule.TariffID,
		rule.FromCount,
		rule.ToCount,
		rule.PercentFee,
		rule.FixedFee,
		rule.MinFee,
		rule.MaxFee,
		rule.CalcMode,
		rule.MCC,
		rule.ClientType,
		rule.AccountType,
		rule.OpType,
	)

	return err
}

// UpdateThresholdRule - изменение правил для порогов
func UpdateThresholdRule(id int, rule model.ThresholdRule) error {
	_, err := DB.Exec(context.Background(), `
		UPDATE threshold_rules
		SET tariff_id = $1,
		    from_count = $2,
		    to_count = $3,
		    percent_fee = $4,
		    fixed_fee = $5,
		    min_fee = $6,
		    max_fee = $7,
		    calc_mode = $8,
		    mcc = $9,
		    client_type = $10,
		    account_type = $11,
		    op_type = $12
		WHERE id = $13
	`,
		rule.TariffID,
		rule.FromCount,
		rule.ToCount,
		rule.PercentFee,
		rule.FixedFee,
		rule.MinFee,
		rule.MaxFee,
		rule.CalcMode,
		rule.MCC,
		rule.ClientType,
		rule.AccountType,
		rule.OpType,
		id,
	)
	return err
}

// DeleteThresholdRule - удаление правил для порогов
func DeleteThresholdRule(id int) error {
	_, err := DB.Exec(context.Background(), `
		DELETE FROM threshold_rules WHERE id = $1
	`, id)
	return err
}

// Клиенты

// ExistsClient проверяет, существует ли клиент с заданным ClientID
func ExistsClient(clientID string) (bool, error) {
	var exists bool
	query := `
        SELECT EXISTS (
            SELECT 1 FROM clients WHERE client_id = $1
        )
    `
	err := DB.QueryRow(context.Background(), query, clientID).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// GetAllClients возвращает список всех клиентов из базы данных
func GetAllClients() ([]model.Client, error) {
	query := `
	   SELECT client_id, tariff_id, client_type, account_type, user_id
	   FROM clients
	`

	rows, err := DB.Query(context.Background(), query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []model.Client

	for rows.Next() {
		var c model.Client
		if err := rows.Scan(
			&c.ClientID,
			&c.TariffID,
			&c.ClientType,
			&c.AccountType,
			&c.UserID,
		); err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}

	return clients, nil
}

// GetClientByUserID - получение клиента по его username
func GetClientByUserID(userID int) (model.Client, error) {
	row := DB.QueryRow(context.Background(), `
		SELECT client_id, tariff_id, client_type, account_type, user_id
		FROM clients
		WHERE user_id = $1
	`, userID)

	var c model.Client
	err := row.Scan(
		&c.ClientID,
		&c.TariffID,
		&c.ClientType,
		&c.AccountType,
		&c.UserID,
	)
	if err != nil {
		return model.Client{}, err
	}

	return c, nil
}

// GetClientByID - получение клиента по его ID
func GetClientByID(id int) (model.Client, error) {
	row := DB.QueryRow(context.Background(), `
		SELECT client_id, tariff_id, client_type, account_type, user_id
		FROM clients
		WHERE client_id = $1
	`, id)

	var c model.Client
	err := row.Scan(&c.ClientID, &c.TariffID, &c.ClientType, &c.AccountType, &c.UserID)
	if err != nil {
		return model.Client{}, err
	}
	return c, nil
}

// CreateClient - добавление нового клиента
func CreateClient(client model.Client) error {
	_, err := DB.Exec(context.Background(), `
		INSERT INTO clients (client_id, tariff_id, client_type, account_type, user_id)
		VALUES ($1, $2, $3, $4, $5)
	`,
		client.ClientID,
		client.TariffID,
		client.ClientType,
		client.AccountType,
		client.UserID,
	)
	return err
}

// UpdateClient - изменение клиента
func UpdateClient(client model.Client) error {
	_, err := DB.Exec(context.Background(), `
		UPDATE clients
		SET tariff_id = $1,
		    client_type = $2,
		    account_type = $3,
			user_id = $4
		WHERE client_id = $5
	`,
		client.TariffID,
		client.ClientType,
		client.AccountType,
		client.UserID,
		client.ClientID,
	)
	return err
}

// DeleteClient - удаление клиента
func DeleteClient(client_id int) error {
	_, err := DB.Exec(context.Background(), `
		DELETE FROM clients WHERE client_id = $1
	`, client_id)
	return err
}

// Пользователи

// GetUserByUsername - получение пользователя из БД при авторизации
func GetUserByUsername(username string) (model.User, error) {
	query := `SELECT id, username, password_hash, role FROM users WHERE username = $1`

	var u model.User
	err := DB.QueryRow(context.Background(), query, username).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role)
	if err != nil {
		return model.User{}, err
	}

	return u, nil
}

// CreateUser - добавление пользователя в БД при регистрации
func CreateUser(username, passwordHash string, role string) error {
	_, err := DB.Exec(context.Background(), `
        INSERT INTO users (username, password_hash, role)
        VALUES ($1, $2, $3)
    `, username, passwordHash, role)

	return err
}

// GetOperationsByClientID - просмотр операций пользователя
func GetOperationsByClientID(clientID string) ([]model.Operation, error) {
	rows, err := DB.Query(context.Background(), `
		SELECT id, client_id, amount, created_at
		FROM operations
		WHERE client_id = $1
		ORDER BY created_at DESC
	`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ops []model.Operation
	for rows.Next() {
		var op model.Operation
		err := rows.Scan(&op.ID, &op.ClientID, &op.Amount, &op.CreatedAt)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}

	return ops, nil
}

// Лимиты (количество и сумма операций за стуки)

// SaveOperation - сохранение операции, совершенной пользователем
func SaveOperation(clientID string, amount float64) error {
	_, err := DB.Exec(context.Background(), `
       INSERT INTO operations (client_id, amount) VALUES ($1, $2)
   `, clientID, amount)
	return err
}

// CountOperationsInLast24h - число операций клиента в сутки
func CountOperationsInLast24h(clientID string) (int, float64, error) {
	query := `
       SELECT COUNT(*), COALESCE(SUM(amount), 0)
       FROM operations
       WHERE client_id = $1 AND created_at >= NOW() - INTERVAL '24 hours'
   `
	var count int
	var total float64

	err := DB.QueryRow(context.Background(), query, clientID).Scan(&count, &total)
	return count, total, err
}

// CalculateByRule - рассчет комиссии по правилам
func CalculateByRule(rule model.ThresholdRule, req model.CalcRequest) float64 {
	fixed := rule.FixedFee
	percent := req.Amount * rule.PercentFee
	base := 0.0

	switch rule.CalcMode {
	case "fixed":
		base = fixed
	case "percent":
		base = percent
	case "fixed_plus_percent":
		base = fixed + percent
	case "min":
		base = math.Min(fixed, percent)
	case "max":
		base = math.Max(fixed, percent)
	default:
		base = fixed + percent // fallback
	}

	if base < rule.MinFee {
		base = rule.MinFee
	}
	if base > rule.MaxFee {
		base = rule.MaxFee
	}

	return base
}
