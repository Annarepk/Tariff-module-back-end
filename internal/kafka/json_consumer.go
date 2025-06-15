package kafka

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"tariff-module-backend/internal/db"
	"tariff-module-backend/internal/model"
	"tariff-module-backend/internal/service"

	kafka "github.com/segmentio/kafka-go"
)

func StartKafkaJSONConsumer(ctx context.Context) {
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: []string{os.Getenv("KAFKA_BROKER")},
		Topic:   os.Getenv("KAFKA_TOPIC_JSON_REQUEST"),
		GroupID: "tariff-module-group",
	})

	writer := kafka.NewWriter(kafka.WriterConfig{
		Brokers: []string{os.Getenv("KAFKA_BROKER")},
		Topic:   os.Getenv("KAFKA_TOPIC_JSON_RESPONSES"),
	})

	go func() {
		for {
			m, err := reader.ReadMessage(ctx)
			if err != nil {
				log.Printf("Kafka read error: %v", err)
				continue
			}

			var req model.CalcRequest
			if err := json.Unmarshal(m.Value, &req); err != nil {
				log.Printf("Ошибка парсинга JSON: %v", err)
				continue
			}

			// Реальный запрос тарифа из БД
			tariff, err := db.GetTariffByClientID(req.ClientID)
			if err != nil {
				log.Printf("Ошибка получения тарифа для клиента %s: %v", req.ClientID, err)
				continue
			}

			// Расчёт комиссии
			resp := service.ProcessKafkaCalculationWithTariff(req, tariff)

			// Ответ
			respBytes, _ := json.Marshal(resp)
			err = writer.WriteMessages(ctx, kafka.Message{
				Key:   []byte(req.ClientID),
				Value: respBytes,
			})
			if err != nil {
				log.Printf("Ошибка отправки Kafka-ответа: %v", err)
			}
		}
	}()
}
