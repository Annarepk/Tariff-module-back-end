package main

// admin admin123
//$2a$10$bycbQmzvOPSoV9mvahBWMucx70IMboHEzfXLdpar1IYRpkw8n26KC

import (
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"

	"tariff-module-backend/internal/db"
	"tariff-module-backend/internal/model"
	"tariff-module-backend/internal/service"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"tariff-module-backend/internal/metrics"
	"time"

	"crypto/rand"
)

func main() {
	db.Connect()
	//ctx := context.Background()

	// Запуск Kafka consumer для JSON
	//go kafka.StartKafkaJSONConsumer(ctx)

	// Запуск Kafka consumer для XML
	//go kafka.StartXMLConsumer()

	// Запуск ISO-сервера
	//go iso.StartISO8583Server()

	r := mux.NewRouter()

	metrics.Init()
	r.HandleFunc("/api/login", LoginHandler).Methods("POST")
	r.Handle("/api/operations/{id}", AuthMiddleware(http.HandlerFunc(GetOperationsHandler))).Methods("GET")

	r.Handle("/api/tariffs", AuthMiddleware(AdminOnly(http.HandlerFunc(CreateTariffHandler)))).Methods("POST")
	r.HandleFunc("/api/tariffs", GetTariffsHandler).Methods("GET")
	r.HandleFunc("/api/tariffs/{id}", GetTariffByIDHandler).Methods("GET")
	r.Handle("/api/tariffs/{id}", AuthMiddleware(AdminOnly(http.HandlerFunc(UpdateTariffHandler)))).Methods("PUT")
	r.Handle("/api/tariffs/{id}", AuthMiddleware(AdminOnly(http.HandlerFunc(DeleteTariffHandler)))).Methods("DELETE")

	r.Handle("/api/rules", AuthMiddleware(AdminOnly(http.HandlerFunc(CreateRuleHandler)))).Methods("POST")
	r.HandleFunc("/api/rules", GetAllRulesHandler).Methods("GET")
	r.Handle("/api/rules/{id}", AuthMiddleware(AdminOnly(http.HandlerFunc(UpdateRuleHandler)))).Methods("PUT")
	r.Handle("/api/rules/{id}", AuthMiddleware(AdminOnly(http.HandlerFunc(DeleteRuleHandler)))).Methods("DELETE")

	r.Handle("/metrics", promhttp.Handler())
	r.HandleFunc("/api/metrics/custom", GetCustomMetricsHandler).Methods("GET")

	r.Handle("/api/clients", AuthMiddleware(http.HandlerFunc(CreateClientHandler))).Methods("POST")
	r.Handle("/api/clients/upload", AuthMiddleware((AdminOnly(http.HandlerFunc(UploadClientsHandler))))).Methods("POST")
	r.Handle("/api/clients", AuthMiddleware(http.HandlerFunc(GetClientsHandler))).Methods("GET")
	r.Handle("/api/clients/{id}", AuthMiddleware(http.HandlerFunc(UpdateClientHandler))).Methods("PUT")
	r.Handle("/api/clients/{id}", AuthMiddleware(http.HandlerFunc(DeleteClientHandler))).Methods("DELETE")

	r.Handle("/api/calculate", AuthMiddleware(http.HandlerFunc(CalculateHandler))).Methods("POST")
	r.HandleFunc("/api/calculate", CalculateHandler).Methods("POST")

	handler := cors.Default().Handler(r)

	fmt.Println("Сервер запущен на порту 8080...")
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

// Пользователь
type contextKey string

const userKey contextKey = "username"

// GenerateCredentials - генерация логина и пароля клиента
func GenerateCredentials() (string, string, error) {
	randomBytes := make([]byte, 4) // 8 hex символов
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", err
	}
	username := "client_" + hex.EncodeToString(randomBytes)

	passBytes := make([]byte, 6) // 12 hex символов
	if _, err := rand.Read(passBytes); err != nil {
		return "", "", err
	}
	password := hex.EncodeToString(passBytes)
	return username, password, nil
}

// CreateClientHandler - регистрация клиента в системе
func CreateClientHandler(w http.ResponseWriter, r *http.Request) {
	var input struct {
		TariffID    int    `json:"tariffId"`
		ClientType  string `json:"clientType"`
		AccountType string `json:"accountType"`
		Role        string `json:"role,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Неверный формат запрос", http.StatusBadRequest)
		return
	}

	// Проверка на пустые поля
	if input.TariffID == 0 {
		http.Error(w, "Обязательные поля отсутствуют", http.StatusBadRequest)
		return
	}

	// Определяем, какая роль будет установлена
	role := "user" // по умолчанию

	if input.Role != "" {
		// Проверка, что токен авторизован и это админ
		tokenUser, ok := r.Context().Value(userKey).(string)
		if !ok || tokenUser == "" {
			http.Error(w, "Недостаточно прав для указания роли", http.StatusForbidden)
			return
		}

		user, err := db.GetUserByUsername(tokenUser)
		if err != nil || user.Role != "admin" {
			http.Error(w, "Только администратор может назначать роли", http.StatusForbidden)
			return
		}

		// Роль разрешено задать
		role = input.Role
	}

	// Генерация username и пароля
	username, password, err := GenerateCredentials()
	if err != nil {
		http.Error(w, "Ошибка генерации данных доступа", http.StatusInternalServerError)
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Ошибка хэширования пароля", http.StatusInternalServerError)
		return
	}

	// Создание пользователя
	err = db.CreateUser(username, string(hashedPassword), role)
	if err != nil {
		http.Error(w, "Ошибка создания пользователя: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Получаем ID созданного пользователя
	user, err := db.GetUserByUsername(username)
	if err != nil {
		http.Error(w, "Ошибка получения пользователя после создания", http.StatusInternalServerError)
		return
	}

	// Создание клиента
	client := model.Client{
		ClientID:    fmt.Sprintf("client_%d", time.Now().UnixNano()),
		TariffID:    input.TariffID,
		ClientType:  input.ClientType,
		AccountType: input.AccountType,
		UserID:      user.ID,
	}

	err = db.CreateClient(client)
	if err != nil {
		http.Error(w, "Ошибка создания клиента: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Ответ с выданными данными
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message":  "Клиент и пользователь созданы",
		"clientId": client.ClientID,
		"username": username,
		"password": password,
	})

}

// LoginHandler - проверка логина и пароля, генерация уникального токена
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Получаем пользователя из БД
	user, err := db.GetUserByUsername(creds.Username)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Сравниваем хэши
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(creds.Password))
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	client, err := db.GetClientByUserID(user.ID)
	if err != nil {
		http.Error(w, "Client not found", http.StatusUnauthorized)
		return
	}

	// Генерация JWT
	token, err := service.GenerateJWT(creds.Username, client.ClientID, user.Role)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Возвращаем токен
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token": token,
	})
}

// AuthMiddleware - авторизация пользователя
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token := authHeader[7:]
		claims, err := service.ValidateJWT(token)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Добавляем имя пользователя в контекст
		ctx := context.WithValue(r.Context(), userKey, claims.Username)
		ctx = context.WithValue(ctx, "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AdminOnly - авторизация админа
func AdminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, ok := r.Context().Value(userKey).(string)
		if !ok || username == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		user, err := db.GetUserByUsername(username)
		if err != nil || user.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GetOperationsHandler - просмотр операций пользователя
func GetOperationsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clientID := vars["id"]

	ops, err := db.GetOperationsByClientID(clientID)
	if err != nil {
		http.Error(w, "Ошибка при получении операций: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ops)
}

// Тарифы

// CreateTariffHandler - добавление нового тарифа
func CreateTariffHandler(w http.ResponseWriter, r *http.Request) {
	var tariff model.Tariff

	if err := json.NewDecoder(r.Body).Decode(&tariff); err != nil {
		http.Error(w, "Неверный формат запроса", http.StatusBadRequest)
		return
	}

	if tariff.Name == "" || tariff.CalcMode == "" {
		http.Error(w, "Название и тип расчета обязательны", http.StatusBadRequest)
		return
	}

	err := db.CreateTariff(tariff)
	if err != nil {
		http.Error(w, "Ошибка при сохранении тарифа: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Тариф успешно создан",
	})
}

// GetTariffsHandler - получение списка всех тарифов
func GetTariffsHandler(w http.ResponseWriter, r *http.Request) {
	tariffs, err := db.GetAllTariffs()
	if err != nil {
		http.Error(w, "Ошибка при получении тарифов: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tariffs)
}

// GetTariffByIDHandler - получение конкретного тарифа
func GetTariffByIDHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Неверный ID тарифа", http.StatusBadRequest)
		return
	}

	tariff, err := db.GetTariffByID(id)
	if err != nil {
		http.Error(w, "Тариф не найден: "+err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tariff)
}

// UpdateTariffHandler - изменение конкретного тарифа
func UpdateTariffHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Неверный ID тарифа", http.StatusBadRequest)
		return
	}

	var updated model.Tariff
	if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
		http.Error(w, "Неверный формат данных", http.StatusBadRequest)
		return
	}

	err = db.UpdateTariff(id, updated)
	if err != nil {
		http.Error(w, "Ошибка при обновлении тарифа: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Тариф обновлён",
	})
}

// DeleteTariffHandler - удаление конкретного тарифа
func DeleteTariffHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Неверный ID тарифа", http.StatusBadRequest)
		return
	}

	err = db.DeleteTariff(id)
	if err != nil {
		http.Error(w, "Ошибка при удалении тарифа: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Тариф удалён",
	})
}

// Пороговые правила тарифов

// CreateRuleHandler - добавление порогового правила
func CreateRuleHandler(w http.ResponseWriter, r *http.Request) {
	var rule model.ThresholdRule

	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Неверный формат данных", http.StatusBadRequest)
		return
	}

	// Простейшая валидация
	if rule.TariffID == 0 || rule.ToCount <= rule.FromCount {
		http.Error(w, "Некорректные границы порога", http.StatusBadRequest)
		return
	}

	// Проверка на максимум 10 порогов
	existingRules, err := db.GetThresholdRulesByTariffID(rule.TariffID)
	if err != nil {
		http.Error(w, "Ошибка при проверке текущих правил: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if len(existingRules) >= 10 {
		http.Error(w, "Превышен лимит: не более 10 порогов на тариф", http.StatusBadRequest)
		return
	}

	err = db.CreateThresholdRule(rule)
	if err != nil {
		http.Error(w, "Ошибка при сохранении правила: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Пороговое правило добавлено",
	})
}

// GetAllRulesHandler - получение пороговых правил всех тарифов
func GetAllRulesHandler(w http.ResponseWriter, r *http.Request) {
	tariffIDStr := r.URL.Query().Get("tariffId")

	var rules []model.ThresholdRule
	var err error

	if tariffIDStr != "" {
		tariffID, convErr := strconv.Atoi(tariffIDStr)
		if convErr != nil {
			http.Error(w, "Неверный параметр tariffId", http.StatusBadRequest)
			return
		}
		rules, err = db.GetThresholdRulesByTariffID(tariffID)
	} else {
		rules, err = db.GetAllThresholdRules()
	}

	if err != nil {
		http.Error(w, "Ошибка при получении правил: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rules)
}

// DeleteRuleHandler - удаление порогового правила
func DeleteRuleHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	err = db.DeleteThresholdRule(id)
	if err != nil {
		http.Error(w, "Ошибка при удалении правила: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Правило удалено",
	})
}

// UpdateRuleHandler - изменение порогового правила
func UpdateRuleHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	var rule model.ThresholdRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Неверный формат данных", http.StatusBadRequest)
		return
	}

	// Проверка общего числа порогов (не более 10)
	existingRules, err := db.GetThresholdRulesByTariffID(rule.TariffID)
	if err != nil {
		http.Error(w, "Ошибка при проверке правил: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if len(existingRules) > 10 {
		http.Error(w, "Превышен лимит: не более 10 порогов на тариф", http.StatusBadRequest)
		return
	}

	err = db.UpdateThresholdRule(id, rule)
	if err != nil {
		http.Error(w, "Ошибка при обновлении правила: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Правило обновлено",
	})
}

// Метрики

// GetCustomMetricsHandler - метрики за минуту, час, день
func GetCustomMetricsHandler(w http.ResponseWriter, r *http.Request) {
	result := map[string]int{
		"requests_last_minute": metrics.CountSince(1 * time.Minute),
		"requests_last_hour":   metrics.CountSince(1 * time.Hour),
		"requests_last_day":    metrics.CountSince(24 * time.Hour),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// Клиенты

// GetClientsHandler - получение списка всех клиентов
func GetClientsHandler(w http.ResponseWriter, r *http.Request) {
	clients, err := db.GetAllClients()
	if err != nil {
		http.Error(w, "Ошибка при получении клиентов: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(clients)
}

// UploadClientsHandler - загрузка справочника клиентов
func UploadClientsHandler(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Не удалось прочитать файл", http.StatusBadRequest)
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.Comma = ','

	headers, err := reader.Read()
	if err != nil {
		http.Error(w, "Не удалось прочитать заголовки", http.StatusBadRequest)
		return
	}

	headerMap := make(map[string]int)
	for i, h := range headers {
		headerMap[h] = i
	}

	required := []string{"ClientID", "TariffID", "ClientType", "AccountType"}
	for _, field := range required {
		if _, ok := headerMap[field]; !ok {
			http.Error(w, "Отсутствует обязательное поле: "+field, http.StatusBadRequest)
			return
		}
	}

	type ClientInfo struct {
		ClientID string `json:"clientId"`
		Username string `json:"username"`
		Password string `json:"password"`
	}

	var createdClients []ClientInfo
	var skipCount, failCount int
	var messages []string

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			failCount++
			messages = append(messages, "Ошибка чтения строки: "+err.Error())
			continue
		}

		clientID := record[headerMap["ClientID"]]
		tariffID, err := strconv.Atoi(record[headerMap["TariffID"]])
		if err != nil || tariffID <= 0 {
			failCount++
			messages = append(messages, fmt.Sprintf("Некорректный TariffID для клиента %s", clientID))
			continue
		}

		exists, err := db.ExistsClient(clientID)
		if err != nil {
			failCount++
			messages = append(messages, fmt.Sprintf("Ошибка проверки клиента %s: %v", clientID, err))
			continue
		}
		if exists {
			skipCount++
			messages = append(messages, fmt.Sprintf("Клиент %s уже существует — пропущен", clientID))
			continue
		}

		// Генерация username/password
		username, password, err := GenerateCredentials()
		if err != nil {
			failCount++
			messages = append(messages, fmt.Sprintf("Ошибка генерации логина/пароля для клиента %s", clientID))
			continue
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			failCount++
			messages = append(messages, fmt.Sprintf("Ошибка хэширования пароля клиента %s", clientID))
			continue
		}

		// Создание пользователя
		err = db.CreateUser(username, string(hashedPassword), "user")
		if err != nil {
			failCount++
			messages = append(messages, fmt.Sprintf("Ошибка создания пользователя для клиента %s: %v", clientID, err))
			continue
		}
		user, err := db.GetUserByUsername(username)
		if err != nil {
			failCount++
			messages = append(messages, fmt.Sprintf("Ошибка получения пользователя %s", username))
			continue
		}

		// Создание клиента
		client := model.Client{
			ClientID:    clientID,
			TariffID:    tariffID,
			ClientType:  record[headerMap["ClientType"]],
			AccountType: record[headerMap["AccountType"]],
			UserID:      user.ID,
		}
		err = db.CreateClient(client)
		if err != nil {
			failCount++
			messages = append(messages, fmt.Sprintf("Ошибка при создании клиента %s: %v", clientID, err))
			continue
		}

		createdClients = append(createdClients, ClientInfo{
			ClientID: clientID,
			Username: username,
			Password: password,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"added":    len(createdClients),
		"skipped":  skipCount,
		"errors":   failCount,
		"messages": messages,
		"clients":  createdClients,
	})
}

// UpdateClientHandler - изменение клиента
func UpdateClientHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем username из контекста
	username, ok := r.Context().Value(userKey).(string)
	if !ok || username == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Получаем пользователя из БД
	user, err := db.GetUserByUsername(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	clientID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Неверный ID", http.StatusBadRequest)
		return
	}

	// Получаем клиента по ID
	client, err := db.GetClientByID(clientID)
	if err != nil {
		http.Error(w, "Клиент не найден", http.StatusNotFound)
		return
	}

	// Проверяем, принадлежит ли клиент текущему пользователю
	if client.UserID != user.ID {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	// Читаем обновлённые данные
	var updated model.Client
	if err := json.NewDecoder(r.Body).Decode(&updated); err != nil {
		http.Error(w, "Неверный формат данных", http.StatusBadRequest)
		return
	}

	// Применяем изменения
	client.TariffID = updated.TariffID
	client.ClientType = updated.ClientType
	client.AccountType = updated.AccountType

	err = db.UpdateClient(updated)
	if err != nil {
		http.Error(w, "Ошибка при обновлении клиента: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Клиент обновлён",
	})
}

// DeleteClientHandler - удаление клиента
func DeleteClientHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем имя пользователя из токена
	username, ok := r.Context().Value(userKey).(string)
	if !ok || username == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Получаем пользователя из БД
	user, err := db.GetUserByUsername(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	// Получаем ID клиента из URL
	vars := mux.Vars(r)
	idStr := vars["id"]
	clientID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Неверный ID клиента", http.StatusBadRequest)
		return
	}

	// Получаем клиента по ID
	client, err := db.GetClientByID(clientID)
	if err != nil {
		http.Error(w, "Клиент не найден", http.StatusNotFound)
		return
	}

	// Проверяем принадлежит ли клиент текущему пользователю
	if client.UserID != user.ID {
		http.Error(w, "Доступ запрещён", http.StatusForbidden)
		return
	}

	// Удаляем клиента
	err = db.DeleteClient(clientID)
	if err != nil {
		http.Error(w, "Ошибка при удалении клиента: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Возвращаем ответ
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "Клиент удалён",
	})
}

// Комиссии

// CalculateHandler - подсчет комиссии
func CalculateHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		duration := time.Since(start).Seconds()
		metrics.RequestCounter.WithLabelValues("/api/calculate").Inc()
		metrics.RequestHistogram.WithLabelValues("/api/calculate").Observe(duration)
	}()

	var req model.CalcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	count, total, err := db.CountOperationsInLast24h(req.ClientID)
	if err != nil {
		http.Error(w, "Ошибка при проверке лимитов", http.StatusInternalServerError)
		return
	}

	if count >= 100 {
		http.Error(w, "Лимит количества операций за сутки превышен", http.StatusForbidden)
		return
	}

	if total+req.Amount > 100_000 {
		http.Error(w, "Превышен лимит суммы за сутки", http.StatusForbidden)
		return
	}

	metrics.RecordRequest()

	// Получаем тариф
	tariff, err := db.GetTariffByClientID(req.ClientID)
	if err != nil {
		http.Error(w, "Не удалось получить тариф: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Получение пороговых правил по тарифу
	rules, err := db.GetThresholdRulesByTariffID(tariff.ID)
	if err != nil {
		http.Error(w, "Ошибка при получении порогов", http.StatusInternalServerError)
		return
	}

	// Фильтрация правил по условиям
	var selectedRule *model.ThresholdRule
	for _, rule := range rules {
		if (rule.MCC == "" || rule.MCC == req.MCC) &&
			(rule.ClientType == "" || rule.ClientType == req.ClientType) &&
			(rule.AccountType == "" || rule.AccountType == req.AccountType) &&
			(rule.OpType == "" || rule.OpType == req.OperationType) &&
			req.OperationCount >= rule.FromCount && req.OperationCount < rule.ToCount {

			selectedRule = &rule
			break
		}
	}

	// Расчёт комиссии
	var commission float64
	if selectedRule != nil {
		commission = db.CalculateByRule(*selectedRule, req)
	} else {
		commission = service.CalculateCommission(tariff, req)
	}

	// Сохраняем операцию в БД
	_ = db.SaveOperation(req.ClientID, req.Amount)

	// Отправляем ответ
	resp := model.CalcResponse{
		Product:        tariff.Name,
		Commission:     commission,
		OperationCount: req.OperationCount,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
