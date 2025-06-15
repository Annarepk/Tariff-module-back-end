package iso

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/moov-io/iso8583"
	"github.com/moov-io/iso8583/field"

	"tariff-module-backend/internal/db"
	"tariff-module-backend/internal/model"
	"tariff-module-backend/internal/service"
)

func StartISO8583Server() {
	port := os.Getenv("ISO8583_PORT")
	if port == "" {
		port = "8583"
	}
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Ошибка запуска ISO8583 сервера: %v", err)
	}
	defer listener.Close()

	log.Println("ISO8583 сервер слушает порт 8583")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Ошибка соединения: %v", err)
			continue
		}
		go handleISOConnection(conn)
	}
}

func sendISOError(conn net.Conn, reason string) {
	spec := buildSpec()
	resp := iso8583.NewMessage(spec)
	resp.MTI("0210")
	_ = resp.Field(4, "000000000000") // 0 комиссия
	_ = resp.Field(48, reason)

	packed, _ := resp.Pack()
	conn.Write(packed)
}

func handleISOConnection(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Ошибка чтения: %v", err)
		return
	}

	spec := buildSpec()
	msg := iso8583.NewMessage(spec)

	if err := msg.Unpack(buffer[:n]); err != nil {
		log.Printf("Ошибка распаковки ISO8583: %v", err)
		return
	}

	clientID, _ := msg.GetField(2).String()
	amountStr, _ := msg.GetField(4).String()
	mcc, _ := msg.GetField(43).String()
	clientType, _ := msg.GetField(60).String()
	accountType, _ := msg.GetField(61).String()
	opType, _ := msg.GetField(62).String()

	amountCents, _ := strconv.Atoi(amountStr)
	amount := float64(amountCents) / 100

	log.Printf("Запрос ISO: clientID=%s, amount=%.2f, mcc=%s, clientType=%s, accountType=%s, opType=%s",
		clientID, amount, mcc, clientType, accountType, opType)

	// Проверка лимитов
	count, total, _ := db.CountOperationsInLast24h(clientID)
	if count >= 100 {
		sendISOError(conn, "Количество операций превышено")
		return
	}
	if total+amount > 100_000 {
		sendISOError(conn, "Превышен лимит суммы")
		return
	}

	// Получаем тариф клиента
	tariff, err := db.GetTariffByClientID(clientID)
	if err != nil {
		log.Printf("Ошибка при получении тарифа: %v", err)
		sendISOError(conn, "Тариф не найден")
		return
	}

	// Считаем комиссию
	req := model.CalcRequest{
		ClientID:      clientID,
		Amount:        amount,
		MCC:           mcc,
		ClientType:    clientType,
		AccountType:   accountType,
		OperationType: opType,
		// OperationCount можно подсчитать из count
		OperationCount: count,
	}
	commission := service.CalculateCommission(tariff, req)

	// Сохраняем операцию (если БД подключена — использовать db.SaveOperation) ---
	_ = db.SaveOperation(clientID, amount)

	// Ответ
	resp := iso8583.NewMessage(spec)
	resp.MTI("0210")
	_ = resp.Field(2, clientID)
	_ = resp.Field(4, fmt.Sprintf("%012.0f", commission*100))
	_ = resp.Field(48, tariff.Name)

	packed, err := resp.Pack()
	if err != nil {
		log.Printf("Ошибка упаковки ответа: %v", err)
		return
	}
	conn.Write(packed)
}

func buildSpec() *iso8583.MessageSpec {
	return &iso8583.MessageSpec{
		Fields: map[int]field.Field{
			0:  field.NewString(&field.Spec{Length: 4, Description: "MTI"}),
			2:  field.NewString(&field.Spec{Length: 19, Description: "Client ID"}),
			4:  field.NewString(&field.Spec{Length: 12, Description: "Amount (копейки)"}),
			48: field.NewString(&field.Spec{Length: 100, Description: "Product name"}),
		},
	}
}
